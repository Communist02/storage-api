import io
import ssl
from typing import Iterable, cast
from minio import Minio
from minio.sse import SseCustomerKey
from minio.error import S3Error
from minio.commonconfig import CopySource
from fastapi import HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from urllib.parse import quote
from minio.deleteobjects import DeleteObject
import truststore
import urllib3
from config import config
from get_token import get_sts_token
import zipstream
from fastapi.concurrency import run_in_threadpool


class S3Client:
    def __init__(self, endpoint: str):
        self.endpoint = endpoint
        self.cert_check = not config.debug_mode
        ssl_context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.http_client = urllib3.PoolManager(
            ssl_context=ssl_context) if self.cert_check else None
        self.admin_client = Minio(
            self.endpoint, 'admin', 'password', secure=True, cert_check=self.cert_check, http_client=self.http_client)

    async def get_list_files(self, bucket_name: str, path: str, recursive: bool, jwt_token: str) -> list[dict]:
        auth = await get_sts_token(jwt_token, 'https://' + config.s3_url, 0)
        if auth is None:
            raise HTTPException(
                status_code=500,
                detail={
                    'error': 'Error receiving the STS token',
                    'message': "Couldn't get the STS token"
                }
            )
        client = Minio(self.endpoint, auth['access_key'], auth['secret_key'],
                       auth['session_token'], secure=True, cert_check=self.cert_check, http_client=self.http_client)

        try:
            if path:
                prefix = path.strip('/') + '/'
                objects = await run_in_threadpool(
                    client.list_objects,
                    bucket_name,
                    recursive=recursive,
                    prefix=prefix
                )
            else:
                objects = await run_in_threadpool(
                    client.list_objects,
                    bucket_name,
                    recursive=recursive
                )
            result = []
            processed_folders = set()

            for obj in objects:
                if obj.object_name:
                    object_name = obj.object_name
                    if not object_name.endswith('NODATA'):
                        file = {
                            'name': obj.object_name[obj.object_name.rfind('/', 0, -1 if obj.is_dir else -2) + 1:],
                            'isDirectory': obj.is_dir,
                            'path': f'/{object_name}',
                            'size': obj.size,
                        }
                        if obj.last_modified:
                            file['updatedAt'] = obj.last_modified.isoformat()
                        result.append(file)

                    if recursive:
                        current_path = ''
                        for part in object_name.split('/')[:-1]:
                            current_path += part + '/'
                            if current_path not in processed_folders:
                                processed_folders.add(current_path)
                                result.append({
                                    'name': part,
                                    'isDirectory': True,
                                    'path': f'/{current_path}'.rstrip('/'),
                                })
            return result
        except S3Error as error:
            print(f'Error fetching files: {error.message}, {error.code}')
            if error.code == 'NoSuchBucket':
                raise HTTPException(
                    status_code=410,
                    detail=f"No such bucket '{bucket_name}': {error.message}"
                )
            elif error.code == 'AccessDenied':
                raise HTTPException(
                    status_code=423,
                    detail=f"Access Denied '{bucket_name}': {error.message}"
                )
            else:
                raise HTTPException(
                    status_code=500,
                    detail={
                        'error': 'Failed to retrieve files',
                        'message': error.message
                    }
                )

    async def get_dir_info(self, bucket_name: str, path: str, jwt_token: str) -> dict[str, int | str]:
        files = await self.get_list_files(bucket_name, path, True, jwt_token)
        count_files = 0
        count_dir = 0
        sum_size = 0
        for file in files:
            if file['isDirectory']:
                count_dir += 1
            else:
                count_files += 1
                sum_size += file['size']
        return {
            'count_files': count_files,
            'count_dir': count_dir,
            'sum_size': sum_size,
            'path': '/' + path.strip('/')
        }

    async def get_buckets(self, jwt_token: str) -> list[str]:
        auth = await get_sts_token(jwt_token, 'https://' + config.s3_url, 0)
        if auth is None:
            raise HTTPException(
                status_code=500,
                detail={
                    'error': 'Error receiving the STS token',
                    'message': "Couldn't get the STS token"
                }
            )
        client = Minio(self.endpoint, auth['access_key'], auth['secret_key'],
                       auth['session_token'], secure=True, cert_check=self.cert_check, http_client=self.http_client)

        try:
            buckets = await run_in_threadpool(client.list_buckets)
            result: list[str] = []

            for bucket in buckets:
                result.append(bucket.name)

            return result
        except S3Error as error:
            print(f'Error fetching files: {error.message}')
            if error.code == 'AccessDenied':
                raise HTTPException(
                    status_code=423,
                    detail=f"Access Denied: {error.message}"
                )
            else:
                raise HTTPException(
                    status_code=500,
                    detail={
                        'error': 'Failed to retrieve files',
                        'message': error.message
                    }
                )

    async def delete_files(self, bucket_name: str, paths: list[str], jwt_token: str):
        auth = await get_sts_token(jwt_token, 'https://' + config.s3_url, 0)
        if auth is None:
            raise HTTPException(
                status_code=500,
                detail={
                    'error': 'Error receiving the STS token',
                    'message': "Couldn't get the STS token"
                }
            )
        client = Minio(self.endpoint, auth['access_key'], auth['secret_key'],
                       auth['session_token'], secure=True, cert_check=self.cert_check, http_client=self.http_client)

        try:
            objects_to_delete: list[DeleteObject] = []

            for path in paths:
                object_name = path.strip('/')

                if not path.endswith('/'):
                    objects_to_delete.append(DeleteObject(object_name))
                else:
                    objects = await run_in_threadpool(
                        client.list_objects,
                        bucket_name, prefix=object_name + '/', recursive=True)
                    objects_to_delete.extend(
                        [DeleteObject(obj.object_name)
                         for obj in objects if obj.object_name]
                    )

            if objects_to_delete:
                errors = await run_in_threadpool(
                    lambda: list(client.remove_objects(
                        bucket_name, objects_to_delete))
                )

                if errors:
                    error_list = [e.__dict__ for e in errors]
                    raise HTTPException(
                        status_code=500,
                        detail={'error': 'Some files failed to delete',
                                'errors': error_list}
                    )

        except S3Error as error:
            print(f'Error deleting files: {error.message}')
            if error.code == 'AccessDenied':
                raise HTTPException(
                    status_code=423,
                    detail=f"Access Denied '{bucket_name}': {error.message}"
                )
            else:
                raise HTTPException(
                    status_code=500,
                    detail={'error': 'S3 error during delete',
                            'message': error.message}
                )

    async def download_file(self, bucket_name: str, file_path: str, preview: bool, encryption_key: SseCustomerKey | None, jwt_token: str, range_header: str | None = None) -> StreamingResponse:
        auth = await get_sts_token(jwt_token, 'https://' + config.s3_url, 0)
        if auth is None:
            raise HTTPException(
                status_code=500,
                detail={
                    'error': 'Error receiving the STS token',
                    'message': "Couldn't get the STS token"
                }
            )
        client = Minio(self.endpoint, auth['access_key'], auth['secret_key'],
                       auth['session_token'], secure=True, cert_check=self.cert_check, http_client=self.http_client)

        async def file_iterator(stream, chunk_size=1024 * 1024):
            while True:
                data = await run_in_threadpool(stream.read, chunk_size)
                if not data:
                    break
                yield data

        object_name = file_path.lstrip('/')
        try:
            stat = await run_in_threadpool(client.stat_object, bucket_name, object_name, ssec=encryption_key)
        except S3Error:
            try:
                stat = await run_in_threadpool(client.stat_object, bucket_name, object_name)
                encryption_key = None
            except S3Error as error:
                print(f'Failed to get the file: {error.message}')
                raise HTTPException(
                    status_code=403,
                    detail=f'Failed to get the file: {error.message}'
                )
        file_size = stat.size
        headers = {
            'Content-Disposition': f"attachment; filename*=UTF-8''{quote(object_name.split('/')[-1])}",
            'Content-Length': str(file_size),
            'Accept-Ranges': 'bytes',
        }

        try:
            if range_header and file_size:
                start_end = range_header.replace('bytes=', '').split('-')
                start = int(start_end[0])
                end = int(start_end[1]) if start_end[1] else file_size - 1

                obj = await run_in_threadpool(
                    client.get_object,
                    bucket_name,
                    object_name=object_name,
                    ssec=encryption_key,
                    offset=start,
                    length=end - start + 1
                )

                headers['Content-Length'] = str(end - start + 1)
                headers['Content-Range'] = f'bytes {start}-{end}/{file_size}'

                return StreamingResponse(
                    file_iterator(obj),
                    media_type='application/octet-stream' if preview else None,
                    headers=headers,
                    status_code=206  # Partial Content
                )
            else:
                obj = await run_in_threadpool(
                    client.get_object,
                    bucket_name,
                    object_name=object_name,
                    ssec=encryption_key
                )
                return StreamingResponse(
                    file_iterator(obj),
                    media_type='application/octet-stream' if preview else None,
                    headers=headers
                )
        except S3Error as error:
            print(f'Failed to get the file: {error.message}')
            if error.code == 'AccessDenied':
                raise HTTPException(
                    status_code=423,
                    detail=f"Access Denied '{bucket_name}': {error.message}"
                )
            else:
                raise HTTPException(
                    status_code=404 if error.code == 'NoSuchKey' else 403,
                    detail=f'Failed to get the file: {error.message}'
                )

    async def download_files(self, bucket_name: str, file_paths: list, encryption_key: SseCustomerKey, jwt_token: str) -> StreamingResponse:
        auth = await get_sts_token(jwt_token, 'https://' + config.s3_url, 0)
        if auth is None:
            raise HTTPException(
                status_code=500,
                detail={
                    'error': 'Error receiving the STS token',
                    'message': "Couldn't get the STS token"
                }
            )
        client = Minio(self.endpoint, auth['access_key'], auth['secret_key'],
                       auth['session_token'], secure=True, cert_check=self.cert_check, http_client=self.http_client)

        files_to_download = []

        try:
            for path in file_paths:
                object_name = path.strip('/')

                if not path.endswith('/'):
                    files_to_download.append(object_name)
                else:
                    objects = await run_in_threadpool(
                        client.list_objects,
                        bucket_name,
                        prefix=object_name + '/',
                        recursive=True
                    )

                    for obj in objects:
                        if obj.object_name and not obj.object_name.endswith('/NODATA'):
                            files_to_download.append(obj.object_name)

            # Создаём потоковый zip-архив
            z = zipstream.ZipFile(mode="w", compression=zipstream.ZIP_DEFLATED)

            for obj_name in files_to_download:
                # Оборачиваем поток MinIO в генератор
                def file_generator(obj_name=obj_name):
                    response = client.get_object(
                        bucket_name,
                        obj_name,
                        ssec=encryption_key
                    )
                    try:
                        for chunk in response.stream(1024 * 1024):
                            yield chunk
                    finally:
                        response.close()
                        response.release_conn()

                # Добавляем в архив "ленивый" источник данных
                await run_in_threadpool(z.write_iter, obj_name, file_generator())

            # Отдаём как стрим
            return StreamingResponse(
                cast(Iterable[bytes], z),
                media_type="application/zip",
                headers={"Content-Disposition": 'attachment; filename="files.zip"'}
            )
        except S3Error as error:
            print(f'Failed to get the file: {error.message}')
            if error.code == 'AccessDenied':
                raise HTTPException(
                    status_code=423,
                    detail=f"Access Denied '{bucket_name}': {error.message}"
                )
            else:
                raise HTTPException(
                    status_code=404 if error.code == 'NoSuchKey' else 403,
                    detail=f'Failed to get the file: {error.message}'
                )

    async def copy_files(self, source_bucket_name: str, source_paths: list[str], destination_bucket_name: str, destination_path: str, source_encryption_key: SseCustomerKey, destination_encryption_key: SseCustomerKey, jwt_token: str):
        auth = await get_sts_token(jwt_token, 'https://' + config.s3_url, 0)
        if auth is None:
            raise HTTPException(
                status_code=500,
                detail={
                    'error': 'Error receiving the STS token',
                    'message': "Couldn't get the STS token"
                }
            )
        client = Minio(self.endpoint, auth['access_key'], auth['secret_key'],
                       auth['session_token'], secure=True, cert_check=self.cert_check, http_client=self.http_client)

        for source in source_paths:
            if source.endswith('/'):  # папка
                prefix = source.lstrip('/')
                try:
                    objects = await run_in_threadpool(
                        client.list_objects,
                        source_bucket_name,
                        prefix=prefix,
                        recursive=True
                    )
                    for obj in objects:
                        object_name = obj.object_name
                        if object_name:
                            relative_path = prefix.strip(
                                '/').split('/')[-1] + '/' + object_name[len(prefix):].lstrip('/')
                            destination_object_name = f'{destination_path.rstrip('/')}/{relative_path}'
                            await run_in_threadpool(
                                client.copy_object,
                                bucket_name=destination_bucket_name,
                                object_name=destination_object_name,
                                source=CopySource(
                                    source_bucket_name, object_name, ssec=source_encryption_key),
                                sse=destination_encryption_key,
                            )
                except S3Error as error:
                    print(f"Failed copy folder '{prefix}': {error.message}")
                    if error.code == 'AccessDenied':
                        raise HTTPException(
                            status_code=423,
                            detail=f"Access Denied '{source_bucket_name}' to '{destination_bucket_name}': {error.message}"
                        )
                    else:
                        raise HTTPException(
                            status_code=500,
                            detail=f"Failed copy folder '{prefix}': {error.message}"
                        )
            else:  # файл
                filename = source.split('/')[-1]
                destination_object_name = f'{destination_path.rstrip('/')}/{filename}'
                object_name = source.lstrip('/')
                try:
                    await run_in_threadpool(
                        client.copy_object,
                        bucket_name=destination_bucket_name,
                        object_name=destination_object_name,
                        source=CopySource(
                            source_bucket_name, object_name, ssec=source_encryption_key),
                        sse=destination_encryption_key,
                    )
                except S3Error as error:
                    print(f"Failed copy file '{object_name}': {error.message}")
                    if error.code == 'AccessDenied':
                        raise HTTPException(
                            status_code=423,
                            detail=f"Access Denied '{source_bucket_name}' to '{destination_bucket_name}': {error.message}"
                        )
                    else:
                        raise HTTPException(
                            status_code=500,
                            detail=f"Failed copy file '{object_name}': {error.message}"
                        )

    async def rename_file(self, bucket_name: str, path: str, new_name: str, encryption_key: SseCustomerKey, jwt_token: str) -> list:
        auth = await get_sts_token(jwt_token, 'https://' + config.s3_url, 0)
        if auth is None:
            raise HTTPException(
                status_code=500,
                detail={
                    'error': 'Error receiving the STS token',
                    'message': "Couldn't get the STS token"
                }
            )
        client = Minio(self.endpoint, auth['access_key'], auth['secret_key'],
                       auth['session_token'], secure=True, cert_check=self.cert_check, http_client=self.http_client)

        object_name = path.strip('/')
        new_object_name = object_name[:-
                                      len(object_name.split('/')[-1])] + new_name
        new_paths = []
        if object_name == new_object_name:
            raise HTTPException(
                status_code=409,
                detail=f"Old and new path equivalent'{bucket_name}': {object_name} = {new_object_name}"
            )

        if path.endswith('/'):  # папка
            prefix = path.strip('/') + '/'
            try:
                objects = await run_in_threadpool(
                    client.list_objects,
                    bucket_name, prefix=prefix, recursive=True
                )
                for obj in objects:
                    object_name = obj.object_name
                    if object_name:
                        relative_path = object_name[len(prefix):].lstrip('/')
                        destination_object_name = f'{new_object_name}/{relative_path}'
                        new_paths.append(destination_object_name)
                        await run_in_threadpool(
                            client.copy_object,
                            bucket_name=bucket_name,
                            object_name=destination_object_name,
                            source=CopySource(
                                bucket_name, object_name, ssec=encryption_key),
                            sse=encryption_key,
                        )
            except S3Error as error:
                print(f"Failed copy folder '{prefix}': {error.message}")
                if error.code == 'AccessDenied':
                    raise HTTPException(
                        status_code=423,
                        detail=f"Access Denied '{bucket_name}': {error.message}"
                    )
                else:
                    raise HTTPException(
                        status_code=500,
                        detail=f"Failed copy folder '{prefix}': {error.message}"
                    )
        else:  # файл
            try:
                await run_in_threadpool(
                    client.copy_object,
                    bucket_name=bucket_name,
                    object_name=new_object_name,
                    source=CopySource(bucket_name, object_name,
                                      ssec=encryption_key),
                    sse=encryption_key,

                )
            except S3Error as error:
                print(f"Failed copy file '{object_name}': {error.message}")
                if error.code == 'AccessDenied':
                    raise HTTPException(
                        status_code=423,
                        detail=f"Access Denied '{bucket_name}': {error.message}"
                    )
                else:
                    raise HTTPException(
                        status_code=500,
                        detail=f"Failed copy file '{object_name}': {error.message}"
                    )

        await self.delete_files(bucket_name, [path], jwt_token)
        return new_paths

    async def upload_file(self, bucket_name: str, file: UploadFile, path: str, encryption_key: SseCustomerKey, jwt_token: str, overwrite=True):
        auth = await get_sts_token(jwt_token, 'https://' + config.s3_url, 0)
        if auth is None:
            raise HTTPException(
                status_code=500,
                detail={
                    'error': 'Error receiving the STS token',
                    'message': "Couldn't get the STS token"
                }
            )
        client = Minio(self.endpoint, auth['access_key'], auth['secret_key'],
                       auth['session_token'], secure=True, cert_check=self.cert_check, http_client=self.http_client)

        if file.filename and file.size:
            object_name = path.strip('/') + '/' + file.filename.strip('/')
            if not overwrite:
                try:
                    await run_in_threadpool(
                        client.stat_object,
                        bucket_name=bucket_name,
                        object_name=object_name,
                        ssec=encryption_key
                    )
                    raise HTTPException(
                        status_code=403,
                        detail='You cannot overwrite the file'
                    )
                except S3Error as error:
                    pass

            await run_in_threadpool(
                client.put_object,
                bucket_name=bucket_name,
                object_name=object_name,
                data=file.file,
                length=file.size,
                sse=encryption_key,
            )

    async def new_folder(self, bucket_name: str, name: str, path: str, encryption_key: SseCustomerKey, jwt_token: str):
        auth = await get_sts_token(jwt_token, 'https://' + config.s3_url, 0)
        if auth is None:
            raise HTTPException(
                status_code=500,
                detail={
                    'error': 'Error receiving the STS token',
                    'message': "Couldn't get the STS token"
                }
            )
        client = Minio(self.endpoint, auth['access_key'], auth['secret_key'],
                       auth['session_token'], secure=True, cert_check=self.cert_check, http_client=self.http_client)
        try:
            await run_in_threadpool(
                client.put_object,
                bucket_name=bucket_name,
                object_name=f'{path.strip('/')}/{name}/NODATA',
                data=io.BytesIO(b''),
                length=0,
                sse=encryption_key,
            )
        except S3Error as error:
            if error.code == 'AccessDenied':
                raise HTTPException(
                    status_code=423,
                    detail=f"Access Denied '{bucket_name}': {error.message}"
                )
            else:
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed create folder '{name}': {error.message}"
                )

    async def create_bucket(self, bucket_name: str, jwt_token: str):
        auth = await get_sts_token(jwt_token, 'https://' + config.s3_url, 0)
        if auth is None:
            raise HTTPException(
                status_code=500,
                detail={
                    'error': 'Error receiving the STS token',
                    'message': "Couldn't get the STS token"
                }
            )
        client = Minio(self.endpoint, auth['access_key'], auth['secret_key'],
                       auth['session_token'], secure=True, cert_check=self.cert_check, http_client=self.http_client)

        try:
            await run_in_threadpool(
                client.make_bucket,
                bucket_name
            )
        except ValueError as error:
            print(f"Failed create bucket '{bucket_name}': {error}")
            raise HTTPException(
                status_code=406,
                detail=f"Failed create bucket '{bucket_name}': {error}"
            )
        except S3Error as error:
            print(
                f"Failed create bucket '{bucket_name}': {error.message}, {error.code}")
            if error.code == 'BucketAlreadyExists' or error.code == 'BucketAlreadyOwnedByYou':
                raise HTTPException(
                    status_code=409,
                    detail=f"Failed create bucket '{bucket_name}': {error.message}"
                )
            else:
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed create bucket '{bucket_name}': {error.message}"
                )

    async def remove_bucket(self, bucket_name: str, jwt_token: str):
        auth = await get_sts_token(jwt_token, 'https://' + config.s3_url, 0)
        if auth is None:
            raise HTTPException(
                status_code=500,
                detail={
                    'error': 'Error receiving the STS token',
                    'message': "Couldn't get the STS token"
                }
            )
        client = Minio(self.endpoint, auth['access_key'], auth['secret_key'],
                       auth['session_token'], secure=True, cert_check=self.cert_check, http_client=self.http_client)
        try:
            await run_in_threadpool(client.remove_bucket, bucket_name)
        except S3Error as error:
            print(
                f"Failed remove bucket '{bucket_name}': {error.message}, {error.code}")
            if error.code == 'BucketNotEmpty':
                raise HTTPException(
                    status_code=406,
                    detail=f"Failed remove bucket '{bucket_name}': {error.message}"
                )
            elif error.code == 'NoSuchBucket':
                raise HTTPException(
                    status_code=410,
                    detail=f"Failed remove bucket '{bucket_name}': {error.message}"
                )
            else:
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed remove bucket '{bucket_name}': {error.message}"
                )
