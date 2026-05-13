from contextlib import asynccontextmanager
import httpx
from minio.sse import SseCustomerKey
from fastapi import Depends, FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import index
from s3_client import S3Client
from policy import create_policy_to_all, create_policy_to_user
from database import MainDatabase
from crypt import hash_reconstruct
from config import config
from opensearch import OpenSearchManager
from validate import get_current_user, validate_token


class CopyRequest(BaseModel):
    source_collection_id: int
    source_paths: list[str]
    destination_collection_id: int
    destination_path: str


class RenameRequest(BaseModel):
    path: str
    new_name: str


class NewFolderRequest(BaseModel):
    name: str
    path: str


class CreateCollectionRequest(BaseModel):
    name: str


class CreateGroupRequest(BaseModel):
    title: str
    description: str


class GiveAccessUserToCollectionRequest(BaseModel):
    collection_id: int
    user_id: int
    access_type_id: int


class GiveAccessGroupToCollectionRequest(BaseModel):
    collection_id: int
    group_id: int
    access_type_id: int


class AddUserToGroupRequest(BaseModel):
    group_id: int
    user_id: int
    role_id: int


class ChangeGroupInfoRequest(BaseModel):
    group_id: int
    title: str
    description: str


class SpecificListCollectionsRequest(BaseModel):
    collection_ids: list[int]


database = MainDatabase()
opensearch = OpenSearchManager()
minio = S3Client(config.s3_url)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Инициализация при запуске
    try:
        await create_policy_to_all(database.get_absolute_access_to_all_collections())
    except httpx.ConnectError:
        print('Не удалось подключится к S3 хранилищу и/или Opensearch')
    # await web_sessions.initialize()
    yield
    # Завершение при остановке
    # await web_sessions.close()

app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_credentials=True,
    allow_headers=["*"]
)


@app.get('/session')
async def check_session(session: dict = Depends(get_current_user)) -> dict[str, str | bool | int]:
    return {'authenticated': True, 'user_id': session['user_id']}


@app.get('/collections')
async def get_list_collections(session: dict = Depends(get_current_user)) -> list | None:
    return database.get_collections(session['user_id'])


@app.post('/collections/specific')
async def get_specific_list_collections(request: SpecificListCollectionsRequest, session: dict = Depends(get_current_user)) -> list:
    return database.get_specific_access_to_all_collections(session['user_id'], request.collection_ids)


@app.get('/collection/{collection_id}/files/{path:path}')  # access+
async def get_list_files(collection_id: int, path: str, recursive: bool = True, session: dict = Depends(get_current_user)) -> list | None:
    access = [1, 2, 3, 4]
    if database.get_type_access(collection_id, session['user_id']) in access:
        try:
            return await minio.get_list_files(database.get_collection_name(collection_id), path, recursive, session['jwt_token'])
        except HTTPException as error:
            database.add_log('get_list_files', error.status_code,
                             {'error': error.detail, 'path': path, 'recursive': recursive}, user_id=session['user_id'], collection_id=collection_id)
            raise error
    else:
        raise HTTPException(
            status_code=403,
            detail='No access'
        )


@app.get('/collection/{collection_id}/file/{path:path}')  # access+
async def get_file(collection_id: int, path: str, request: Request, token: str, preview: bool = False) -> StreamingResponse:
    session = await validate_token(token)
    if not session:
        raise HTTPException(
            status_code=401,
            detail='Token is invalid or expired'
        )

    access = [1, 2, 3]
    if database.get_type_access(collection_id, session['user_id']) in access:
        try:
            key = hash_reconstruct(session['hash1'], session['hash2'])
            collection_key = database.get_collection_key(
                collection_id, session['user_id'], key)
            path = path.strip('/')
            range_header = request.headers.get('Range')
            return await minio.download_file(database.get_collection_name(collection_id), path, preview, SseCustomerKey(collection_key), session['jwt_token'], range_header=range_header)
        except Exception as error:
            database.add_log('get_file', 500,
                             {'error': str(error), 'path': path, 'preview': preview}, user_id=session['user_id'], collection_id=collection_id)
            raise error
    else:
        raise HTTPException(
            status_code=403,
            detail='No access'
        )


@app.get('/collection/{collection_id}/archive')  # access+
async def get_files(collection_id: int, files: str, token: str) -> StreamingResponse:
    session = await validate_token(token)
    if not session:
        raise HTTPException(
            status_code=401,
            detail='Token is invalid or expired'
        )

    access = [1, 2, 3]
    if database.get_type_access(collection_id, session['user_id']) in access:
        try:
            key = hash_reconstruct(session['hash1'], session['hash2'])
            collection_key = database.get_collection_key(
                collection_id, session['user_id'], key)
            return await minio.download_files(database.get_collection_name(collection_id), files.split('|'), SseCustomerKey(collection_key), session['jwt_token'])
        except Exception as error:
            database.add_log('get_files', 500, {
                'error': str(error), 'files': files}, user_id=session['user_id'], collection_id=collection_id)
            raise error
    else:
        raise HTTPException(
            status_code=403,
            detail='No access'
        )


@app.delete('/collection/{collection_id}/files')  # access+
async def delete_files(collection_id: int, files: str, session: dict = Depends(get_current_user)):
    access = [1, 2]
    access_type = database.get_type_access(
        collection_id, session['user_id'])
    files_list = files.split('|')
    if access_type in access:
        try:
            collection_name = database.get_collection_name(collection_id)
            await minio.delete_files(collection_name, files_list, session['jwt_token'])
            database.add_log(
                'delete_files', 200, {'files': files_list}, user_id=session['user_id'], collection_id=collection_id)
            await index.delete_index(collection_id, collection_name, files_list)
        except Exception as error:
            database.add_log('delete_files', 500, {
                'error': str(error), 'files': files_list}, user_id=session['user_id'], collection_id=collection_id)
            raise error
    else:
        database.add_log(
            'delete_files', 403, {'error': f'{access_type} not in {access}', 'files': files}, user_id=session['user_id'], collection_id=collection_id)
        raise HTTPException(
            status_code=403,
            detail='No access'
        )


@app.post('/copy')  # access+
async def copy_files(request: CopyRequest, session: dict = Depends(get_current_user)):
    access = [1, 2, 3]
    access_dest = [1, 2, 4]
    if database.get_type_access(request.source_collection_id, session['user_id']) in access and database.get_type_access(request.destination_collection_id, session['user_id']) in access_dest:
        try:
            key = hash_reconstruct(session['hash1'], session['hash2'])
            source_collection_key = database.get_collection_key(
                request.source_collection_id, session['user_id'], key)
            destination_collection_key = database.get_collection_key(
                request.destination_collection_id, session['user_id'], key)
            collection_name = database.get_collection_name(
                request.destination_collection_id)
            await minio.copy_files(database.get_collection_name(request.source_collection_id), request.source_paths, collection_name, request.destination_path, SseCustomerKey(source_collection_key), SseCustomerKey(destination_collection_key), session['jwt_token'])
            database.add_log('copy_files', 200, {'source_collection_id': request.source_collection_id, 'source_paths': request.source_paths,
                                                 'destination_path': request.destination_path}, user_id=session['user_id'], collection_id=request.destination_collection_id)
            await index.create_index(request.destination_collection_id, collection_name, jwt_token=session['jwt_token'], encryption_key=database.get_collection_key(request.destination_collection_id, session['user_id'], key), path=request.destination_path)
        except Exception as error:
            database.add_log('copy_files', 500, {
                'error': str(error), 'source_collection_id': request.source_collection_id, 'source_paths': request.source_paths,
                'destination_path': request.destination_path}, user_id=session['user_id'], collection_id=request.destination_collection_id)
            raise error
    else:
        database.add_log('copy_files', 403, {'source_collection_id': request.source_collection_id, 'source_paths': request.source_paths,
                                             'destination_path': request.destination_path}, user_id=session['user_id'], collection_id=request.destination_collection_id)
        raise HTTPException(
            status_code=403,
            detail='No access'
        )


@app.post('/collection/{collection_id}/rename')  # access+
async def rename_file(collection_id: int, request: RenameRequest, session: dict = Depends(get_current_user)):
    access = [1, 2]
    access_type = database.get_type_access(
        collection_id, session['user_id'])
    if access_type in access:
        try:
            key = hash_reconstruct(session['hash1'], session['hash2'])
            collection_key = database.get_collection_key(
                collection_id, session['user_id'], key)
            collection_name = database.get_collection_name(collection_id)
            new_paths = await minio.rename_file(collection_name, request.path, request.new_name, SseCustomerKey(collection_key), session['jwt_token'])
            database.add_log(
                'rename', 200, {'path': request.path, 'new_name': request.new_name}, user_id=session['user_id'], collection_id=collection_id)
            await index.indexing_files(collection_id, collection_name, jwt_token=session['jwt_token'], encryption_key=collection_key, files=new_paths)
            await index.delete_index(collection_id, collection_name, [request.path])
        except Exception as error:
            database.add_log('rename', 500, {
                'error': str(error), 'path': request.path, 'new_name': request.new_name}, user_id=session['user_id'], collection_id=collection_id)
            raise error
    else:
        database.add_log(
            'rename', 403, {'error': f'{access_type} not in {access}', 'path': request.path, 'new_name': request.new_name}, user_id=session['user_id'], collection_id=collection_id)
        raise HTTPException(
            status_code=403,
            detail='No access'
        )


@app.post('/collection/{collection_id}/create_folder')  # access+
async def create_folder(collection_id: int, request: NewFolderRequest, session: dict = Depends(get_current_user)):
    access = [1, 2, 4]
    access_type = database.get_type_access(
        collection_id, session['user_id'])
    if access_type in access:
        try:
            key = hash_reconstruct(session['hash1'], session['hash2'])
            collection_key = database.get_collection_key(
                collection_id, session['user_id'], key)
            await minio.new_folder(database.get_collection_name(collection_id), request.name, request.path, SseCustomerKey(collection_key), session['jwt_token'])
            database.add_log(
                'create_folder', 200, {'path': request.path, 'name': request.name}, user_id=session['user_id'], collection_id=collection_id)
        except Exception as error:
            database.add_log('create_folder', 500, {
                'error': str(error), 'path': request.path, 'name': request.name}, user_id=session['user_id'], collection_id=collection_id)
            raise error
    else:
        database.add_log(
            'create_folder', 403, {'error': f'{access_type} not in {access}', 'path': request.path, 'name': request.name}, user_id=session['user_id'], collection_id=collection_id)
        raise HTTPException(
            status_code=403,
            detail='No access'
        )


@app.post('/collection/{collection_id}/upload/{path:path}')  # access+
@app.post('/collection/{collection_id}/upload')
async def upload_file(file: UploadFile, collection_id: int, path: str = '/', session: dict = Depends(get_current_user)) -> str | None:
    access = [1, 2, 4]
    access_type = database.get_type_access(
        collection_id, session['user_id'])
    if access_type in access:
        try:
            key = hash_reconstruct(session['hash1'], session['hash2'])
            collection_key = database.get_collection_key(
                collection_id, session['user_id'], key)
            collection_name = database.get_collection_name(collection_id)
            await minio.upload_file(collection_name, file, path, SseCustomerKey(collection_key), session['jwt_token'], overwrite=access_type != 4)
            database.add_log(
                'upload', 200, {'file_name': file.filename, 'path': path}, user_id=session['user_id'], collection_id=collection_id)
            await index.indexing_files(collection_id, collection_name, jwt_token=session['jwt_token'], encryption_key=collection_key, files=[path.strip('/') + ('/' + file.filename.strip('/')) if file.filename is not None else ''])
            return file.filename
        except Exception as error:
            database.add_log('upload_file', 500, {
                'error': str(error), 'path': path, 'file_name': file.filename}, user_id=session['user_id'], collection_id=collection_id)
            raise error
    else:
        database.add_log(
            'upload', 403, {'error': f'{access_type} not in {access}', 'path': path, 'file_name': file.filename}, user_id=session['user_id'], collection_id=collection_id)
        raise HTTPException(
            status_code=403,
            detail='No access'
        )


@app.post('/create_collection')  # safe+ logs+
async def create_collection(request: CreateCollectionRequest, session: dict = Depends(get_current_user)) -> int:
    try:
        request.name = request.name.strip()
        await minio.create_bucket(request.name, session['jwt_token'])
        collection_id = database.create_collection(
            request.name, session['user_id'])
        database.add_log('create_collection', 200,
                         {'name': request.name}, user_id=session['user_id'], collection_id=collection_id)
        username = database.get_username(session['user_id'])
        if username:
            await create_policy_to_user(username, database.get_collections(session['user_id']))
    except HTTPException as error:
        database.add_log('create_collection', error.status_code,
                         {'error': error.detail, 'name': request.name}, user_id=session['user_id'])
        raise error
    except Exception as error:
        database.add_log('create_collection_after_create_bucket', 500,
                         {'error': str(error), 'name': request.name}, user_id=session['user_id'])
        raise error
    return collection_id


@app.post('/give_access_user_to_collection')  # safe+ access- logs+
async def give_access_user_to_collection(request: GiveAccessUserToCollectionRequest, session: dict = Depends(get_current_user)):
    key = hash_reconstruct(session['hash1'], session['hash2'])
    try:
        database.give_access_user_to_collection(
            request.collection_id, session['user_id'], request.user_id, request.access_type_id, key)
        database.add_log('give_access_user_to_collection',
                         200, {'access_type_id': request.access_type_id}, user_id=session['user_id'], collection_id=request.collection_id)
        username = database.get_username(session['user_id'])
        if username:
            await create_policy_to_user(username,
                                        database.get_collections(request.user_id))
    except Exception as error:
        database.add_log('give_access_user_to_collection',
                         500, {'error': str(error), 'access_type_id': request.access_type_id}, user_id=session['user_id'], collection_id=request.collection_id)
        raise error


@app.post('/create_group')  # safe+ logs+
async def create_group(request: CreateGroupRequest, session: dict = Depends(get_current_user)):
    try:
        group_id = database.create_group(
            session['user_id'], request.title, request.description)
        database.add_log(
            'create_group', 200, {'title': request.title, 'description': request.description}, user_id=session['user_id'], group_id=group_id)
    except Exception as error:
        database.add_log('create_group', 500, {'error': str(
            error), 'title': request.title, 'description': request.description}, user_id=session['user_id'])
        raise error


@app.post('/give_access_group_to_collection')  # safe+ access- logs+
async def give_access_group_to_collection(request: GiveAccessGroupToCollectionRequest, session: dict = Depends(get_current_user)):
    key = hash_reconstruct(session['hash1'], session['hash2'])
    try:
        access_id = database.give_access_group_to_collection(
            request.collection_id, session['user_id'], request.group_id, request.access_type_id, key)
        database.add_log('give_access_group_to_collection',
                         200, {'access_id': access_id}, user_id=session['user_id'], group_id=request.group_id, collection_id=request.collection_id)
        for user in database.get_group_users(request.group_id, session['user_id']):
            await create_policy_to_user(
                user['username'], database.get_collections(user['id']))
    except Exception as error:
        database.add_log('give_access_group_to_collection',
                         500, {'error': str(error)}, user_id=session['user_id'], group_id=request.group_id, collection_id=request.collection_id)
        raise error


@app.post('/add_user_to_group')  # safe+ logs+
async def add_user_to_group(request: AddUserToGroupRequest, session: dict = Depends(get_current_user)):
    key = hash_reconstruct(session['hash1'], session['hash2'])
    try:
        database.add_user_to_group(
            request.group_id, session['user_id'], request.user_id, request.role_id, key)
        database.add_log('add_user_to_group', 200,
                         {'role_id': request.role_id, 'user_id': request.user_id}, user_id=session['user_id'], group_id=request.group_id)
        username = database.get_username(request.user_id)
        if username:
            await create_policy_to_user(username,
                                        database.get_collections(request.user_id))
    except Exception as error:
        database.add_log('add_user_to_group', 500, {'error': str(
            error), 'role_id': request.role_id, 'user_id': request.user_id}, user_id=session['user_id'], group_id=request.group_id)
        raise error


@app.get('/groups')  # safe+
async def get_groups(session: dict = Depends(get_current_user)) -> list | None:
    return database.get_groups(session['user_id'])


@app.delete('/collection/{collection_id}')  # safe+ logs+
async def remove_collection(collection_id: int, session: dict = Depends(get_current_user)):
    collection_name = database.get_collection_name(collection_id)
    try:
        await minio.remove_bucket(database.get_collection_name(collection_id), session['jwt_token'])
    except HTTPException as error:
        database.add_log('remove_collection', error.status_code, {
                         'error': error.detail, 'collection_id': collection_id, 'collection_name': collection_name}, user_id=session['user_id'])
        if error.status_code != 410:
            raise error
    database.remove_collection(collection_id, session['user_id'])
    database.add_log('remove_collection', 200, {
                     'collection_id': collection_id, 'collection_name': collection_name}, user_id=session['user_id'])
    username = database.get_username(session['user_id'])
    if username:
        await create_policy_to_user(username, database.get_collections(session['user_id']))


@app.get('/other_users')  # safe+
async def get_other_users(session: dict = Depends(get_current_user)) -> list | None:
    return database.get_other_users(session['user_id'])


@app.get('/collection/{collection_id}/access')  # safe+
async def get_access_to_collection(collection_id: int, session: dict = Depends(get_current_user)) -> list | None:
    return database.get_access_to_collection(collection_id, session['user_id'])


@app.delete('collections/access')  # safe+ logs+
async def delete_access_to_collection(access_id: int, session: dict = Depends(get_current_user)) -> list | None:
    try:
        access_info = database.get_access_info(access_id)
        database.delete_access_to_collection(access_id, session['user_id'])
        database.add_log('delete_access_to_collection', 200, {
                         'access_id': access_id}, user_id=session['user_id'])
        if access_info['user_id'] is not None:
            username = database.get_username(access_info['user_id'])
            if username:
                await create_policy_to_user(username,
                                            database.get_collections(access_info['user_id']))
        elif access_info['group_id'] is not None:
            for user in database.get_group_users(access_info['group_id'], session['user_id']):
                await create_policy_to_user(
                    user['username'], database.get_collections(user['id']))
    except Exception as error:
        database.add_log('delete_access_to_collection', 500, {
                         'error': str(error), 'access_id': access_id}, user_id=session['user_id'])
        raise error


@app.delete('/user_to_group')  # safe+ logs+
async def delete_user_to_group(group_id: int, user_id: int, session: dict = Depends(get_current_user)) -> list | None:
    try:
        database.delete_user_to_group(
            group_id, user_id, session['user_id'])
        database.add_log('delete_user_to_group', 200, {
                         'user_id': user_id}, user_id=session['user_id'], group_id=group_id)
        username = database.get_username(user_id)
        if username:
            await create_policy_to_user(username, database.get_collections(user_id))
    except Exception as error:
        database.add_log('delete_user_to_group', 500, {'error': str(
            error), 'user_id': user_id}, user_id=session['user_id'], group_id=group_id)
        raise error


@app.get('/group_users')  # safe+
async def get_group_users(group_id: int, session: dict = Depends(get_current_user)) -> list | None:
    try:
        return database.get_group_users(group_id, session['user_id'])
    except Exception as error:
        database.add_log('get_group_users', 500, {'error': str(
            error), 'user_id': session['user_id']}, user_id=session['user_id'], group_id=group_id)
        raise error


@app.get('/access_types')  # safe+
async def get_access_types(session: dict = Depends(get_current_user)) -> list | None:
    try:
        return database.get_access_types()
    except Exception as error:
        database.add_log('get_access_types', 500, {'error': str(
            error)}, user_id=session['user_id'])
        raise error


@app.post('/transfer_power_to_group')  # safe+
async def transfer_power_to_group(group_id: int, user_id: int, session: dict = Depends(get_current_user)):
    try:
        database.transfer_power_to_group(
            group_id, session['user_id'], user_id)
        database.add_log('transfer_power_to_group', 200, {
            'user_id': user_id}, user_id=session['user_id'], group_id=group_id)
    except Exception as error:
        database.add_log('transfer_power_to_group', 500, {'error': str(
            error), 'user_id': user_id}, user_id=session['user_id'], group_id=group_id)
        raise error


@app.post('/exit_group')  # safe+ logs+
async def exit_group(group_id: int, session: dict = Depends(get_current_user)):
    try:
        database.delete_user_to_group(
            group_id, session['user_id'], session['user_id'])
        database.add_log('exit_group', 200, {},
                         user_id=session['user_id'], group_id=group_id)
        username = database.get_username(session['user_id'])
        if username:
            await create_policy_to_user(username, database.get_collections(session['user_id']))
    except Exception as error:
        database.add_log('exit_group', 500, {'error': str(error)},
                         user_id=session['user_id'], group_id=group_id)
        raise error


@app.post('/change_role_in_group')  # safe+ logs+
async def change_role_in_group(group_id: int, user_id: int, role_id: int, session: dict = Depends(get_current_user)):
    try:
        database.change_role_in_group(
            group_id, session['user_id'], user_id, role_id)
        database.add_log('change_role_in_group', 200, {'user_id': user_id, 'role_id': role_id},
                         user_id=session['user_id'], group_id=group_id)
    except Exception as error:
        database.add_log('change_role_in_group', 500, {'error': str(error), 'user_id': user_id, 'role_id': role_id},
                         user_id=session['user_id'], group_id=group_id)
        raise error


@app.get('/user_info')  # safe+
async def get_user_info(session: dict = Depends(get_current_user)) -> dict[str, int | str]:
    try:
        return database.get_user_info(session['user_id'])
    except Exception as error:
        database.add_log('get_user_info', 500, {'error': str(
            error)}, user_id=session['user_id'])
        raise error


@app.post('/change_access_type')  # safe+ logs+
async def change_access_type(access_id: int, access_type_id: int, session: dict = Depends(get_current_user)):
    try:
        database.change_access_type(
            access_id, session['user_id'], access_type_id)
        database.add_log('change_access_type', 200, {'access_id': access_id, 'access_type_id': access_type_id},
                         user_id=session['user_id'])
        access_info = database.get_access_info(access_id)
        if access_info['user_id'] is not None:
            username = database.get_username(access_info['user_id'])
            if username:
                await create_policy_to_user(username, database.get_collections(access_info['user_id']))
        elif access_info['group_id'] is not None:
            for user in database.get_group_users(access_info['group_id'], session['user_id']):
                await create_policy_to_user(
                    user['username'], database.get_collections(user['id']))
    except Exception as error:
        database.add_log('change_access_type', 500, {'error': str(
            error), 'access_id': access_id, 'access_type_id': access_type_id}, user_id=session['user_id'])
        raise error


@app.post('/change_group_info')  # safe+ logs+
async def change_group_info(request: ChangeGroupInfoRequest, session: dict = Depends(get_current_user)):
    try:
        database.change_group_info(
            session['user_id'], request.group_id, request.title, request.description)
        database.add_log('change_group_info', 200, {'title': request.title, 'description': request.description},
                         user_id=session['user_id'], group_id=request.group_id)
    except Exception as error:
        database.add_log('change_group_info', 500, {'error': str(
            error), 'title': request.title, 'description': request.description}, user_id=session['user_id'], group_id=request.group_id)
        raise error


@app.get('/logs')  # safe+
async def get_logs(session: dict = Depends(get_current_user)) -> list:
    try:
        return database.get_logs(session['user_id'])
    except Exception as error:
        database.add_log('get_logs', 500, {'error': str(
            error)}, user_id=session['user_id'])
        raise error


@app.get('/collection/{collection_id}/history')  # safe+
async def get_history_collection(collection_id: int, session: dict = Depends(get_current_user)) -> list:
    return database.get_history_collection(session['user_id'], collection_id)


@app.post('/collection/{collection_id}/change_info')  # safe+ logs+
async def change_collection_info(collection_id: int, data: dict, session: dict = Depends(get_current_user)):
    access = [1]
    if database.get_type_access(collection_id, session['user_id']) in access:
        try:
            data['collection_id'] = collection_id
            data['collection_name'] = database.get_collection_name(
                collection_id)
            await opensearch.update_document(collection_id, data)
            database.add_log('change_collection_info', 200, None,
                             user_id=session['user_id'], collection_id=collection_id)
        except Exception as error:
            database.add_log('change_collection_info', 500, {'error': str(
                error), 'data': data}, user_id=session['user_id'], collection_id=collection_id)
            raise error
    else:
        raise HTTPException(
            status_code=403,
            detail='You not owner'
        )


@app.get('/collection/{collection_id}/info')  # safe+ logs+
async def get_collection_info(collection_id: int, session: dict = Depends(get_current_user)) -> dict | None:
    access = [1, 2, 3, 4]
    if database.get_type_access(collection_id, session['user_id']) in access:
        try:
            return await opensearch.get_document(collection_id)
        except Exception as error:
            database.add_log('get_collection_info', 500, {'error': str(
                error)}, user_id=session['user_id'], collection_id=collection_id)
            raise error
    else:
        raise HTTPException(
            status_code=403,
            detail='No access'
        )


# safe+ logs+
@app.get('/collection/{collection_id}/file_info/{path:path}')
async def get_file_info(collection_id: int, path: str, is_dir: bool, session: dict = Depends(get_current_user)) -> dict | None:
    access = [1, 2, 3, 4]
    if database.get_type_access(collection_id, session['user_id']) in access:
        try:
            if is_dir:
                return await minio.get_dir_info(database.get_collection_name(collection_id), path, session['jwt_token'])
            else:
                return await opensearch.get_document(f'{collection_id}/{path.strip('/')}', config.opensearch_files_index)
        except Exception as error:
            database.add_log('get_file_info', 500, {'error': str(
                error), 'path': path}, user_id=session['user_id'], collection_id=collection_id)
            raise error
    else:
        raise HTTPException(
            status_code=403,
            detail='No access'
        )


@app.get('/collections/search')  # safe+ logs+
async def search_collection(text: str, session: dict = Depends(get_current_user)) -> list:
    try:
        collections_result = []
        documents = await opensearch.search_collections(text, jwt_token=session['jwt_token'])
        collections = database.get_collections(
            session['user_id'], accessed_to_all=True)
        for document in documents['collections']:
            collection = list(
                filter(lambda x: x['id'] == int(document['_id']), collections))
            if len(collection) > 0:
                collection[0]['index'] = document['_source']
                collection[0]['files'] = [
                    x['_source']
                    for x in documents['files']
                    if x['_source']['collection_id'] == int(document['_id'])
                ]
                collections_result.append(collection[0])
        for file in documents['files']:
            collection = list(filter(
                lambda x: x['id'] == file['_source']['collection_id'], collections_result))
            if len(collection) == 0:
                collection = list(
                    filter(lambda x: x['id'] == file['_source']['collection_id'], collections))
                if len(collection) > 0:
                    collection[0]['files'] = [
                        x['_source']
                        for x in documents['files']
                        if x['_source']['collection_id'] == file['_source']['collection_id']
                    ]
                    collections_result.append(collection[0])
        return collections_result
    except Exception as error:
        database.add_log('search_collection_info', 500, {'error': str(
            error), 'text': text}, user_id=session['user_id'])
        raise error


@app.post('/collection/{collection_id}/change_access_to_all')  # safe+ logs+
async def change_access_to_all(collection_id: int, is_access: bool, session: dict = Depends(get_current_user)):
    if database.get_type_access(collection_id, session['user_id']) == 1:
        key = hash_reconstruct(session['hash1'], session['hash2'])
        try:
            database.change_access_to_all(
                session['user_id'], collection_id, is_access, key)
            database.add_log('change_access_to_all', 200, {'is_access': is_access},
                             user_id=session['user_id'], collection_id=collection_id)
            await create_policy_to_all(
                database.get_absolute_access_to_all_collections())
        except Exception as error:
            database.add_log('change_access_to_all', 500, {'error': str(
                error), 'is_access': is_access}, user_id=session['user_id'], collection_id=collection_id)
            raise error


@app.post('/collection/{collection_id}/indexing_file/{path:path}')
async def indexing_file(collection_id: int, path: str, session: dict = Depends(get_current_user)):
    access = [1, 2, 3, 4]
    access_type = database.get_type_access(
        collection_id, session['user_id'])
    if access_type in access:
        key = hash_reconstruct(session['hash1'], session['hash2'])
        try:
            collection_key = database.get_collection_key(
                collection_id, session['user_id'], key)
            collection_name = database.get_collection_name(collection_id)
            await index.indexing_files(collection_id, collection_name, jwt_token=session['jwt_token'], encryption_key=collection_key, files=['/' + path.strip('/')])
            database.add_log(
                'indexing_file', 200, {'path': path}, user_id=session['user_id'], collection_id=collection_id)
        except Exception as error:
            database.add_log('indexing_file', 500, {'error': str(
                error), 'path': path}, user_id=session['user_id'], collection_id=collection_id)
            raise error
    else:
        database.add_log(
            'index_file', 403, {'error': f'{access_type} not in {access}', 'path': path}, user_id=session['user_id'], collection_id=collection_id)
        raise HTTPException(
            status_code=403,
            detail='No access'
        )
