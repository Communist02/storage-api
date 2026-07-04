from datetime import datetime
from fastapi import HTTPException
from sqlalchemy import JSON, DateTime, VARCHAR, Column, LargeBinary, INT, ForeignKey, TEXT, Index, delete, desc, event, exists, update, func
from sqlalchemy.orm import DeclarativeBase, Session
from sqlalchemy import create_engine, select, insert
import secrets
import crypt
from config import config
from sqlalchemy.exc import IntegrityError


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = 'users'
    __table_args__ = {'schema': 'users'}

    id = Column(INT, primary_key=True, autoincrement=True)
    username = Column(VARCHAR(64), nullable=False)
    encrypted_private_key = Column(LargeBinary(48), nullable=False)
    public_key = Column(LargeBinary(32), nullable=False)


class Group(Base):
    __tablename__ = 'groups'
    __table_args__ = {'schema': 'users'}

    id = Column(INT, primary_key=True, autoincrement=True)
    title = Column(VARCHAR(128), nullable=False)
    description = Column(TEXT, nullable=False)
    public_key = Column(LargeBinary(32), nullable=False)


class UserRole(Base):
    __tablename__ = 'user_roles'
    __table_args__ = {'schema': 'users'}

    id = Column(INT, primary_key=True)
    name = Column(VARCHAR(20))


class GroupUser(Base):
    __tablename__ = 'group_users'
    __table_args__ = {'schema': 'users'}

    user_id = Column(ForeignKey(User.id), primary_key=True)
    group_id = Column(ForeignKey(Group.id), primary_key=True)
    role_id = Column(ForeignKey(UserRole.id), nullable=False)
    encrypted_private_key = Column(LargeBinary(92), nullable=False)


class AccessType(Base):
    __tablename__ = 'access_types'
    __table_args__ = {'schema': 'storage'}

    id = Column(INT, primary_key=True)
    name = Column(VARCHAR(255), nullable=False)


class Collection(Base):
    __tablename__ = 'collections'
    __table_args__ = {'schema': 'storage'}

    id = Column(INT, primary_key=True, autoincrement=True)
    name = Column(VARCHAR(63), nullable=False, unique=True)
    key = Column(LargeBinary(32), nullable=True)


class AccessToCollection(Base):
    __tablename__ = 'access_to_collections'

    id = Column(INT, primary_key=True, autoincrement=True)
    collection_id = Column(ForeignKey(Collection.id), nullable=False)
    encrypted_key = Column(LargeBinary(92), nullable=False)
    type_id = Column(ForeignKey(AccessType.id), nullable=False)
    user_id = Column(ForeignKey(User.id), nullable=True)
    group_id = Column(ForeignKey(Group.id), nullable=True)

    __table_args__ = (
        Index('ux_collection_user', collection_id, user_id,
              unique=True, postgresql_where=user_id.isnot(None)),
        Index('ux_collection_group', collection_id, group_id,
              unique=True, postgresql_where=group_id.isnot(None)),
    )
    __table_args__ = {'schema': 'storage'}


class Log(Base):
    __tablename__ = 'logs'
    __table_args__ = {'schema': 'logs'}

    id = Column(INT, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, nullable=False)
    action = Column(VARCHAR(128), nullable=False)
    detail = Column(JSON, nullable=True)
    status = Column(INT, nullable=False)
    user_id = Column(ForeignKey(User.id), nullable=True)
    group_id = Column(ForeignKey(Group.id), nullable=True)
    collection_id = Column(ForeignKey(Collection.id), nullable=True)


@event.listens_for(AccessType.__table__, 'after_create')
def insert_initial_access_types(target, connection, **kw):
    connection.execute(target.insert(), [
        {'id': 1, 'name': 'owner'},
        {'id': 2, 'name': 'readwrite'},
        {'id': 3, 'name': 'readonly'},
        {'id': 4, 'name': 'writeonly'},
    ])


@event.listens_for(UserRole.__table__, 'after_create')
def insert_initial_user_roles(target, connection, **kw):
    connection.execute(target.insert(), [
        {'id': 1, 'name': 'owner'},
        {'id': 2, 'name': 'admin'},
        {'id': 3, 'name': 'member'},
    ])


class MainDatabase:
    def __init__(self):
        self.engine = create_engine(
            f'postgresql+psycopg2://{config.db_user}:{config.db_password}@{config.db_host}/{config.db_name}',
            pool_pre_ping=True,
            pool_recycle=3600,
            pool_size=10,
            max_overflow=20,
            echo=False,
        )
        self.connection = self.engine.connect()
        # Base.metadata.create_all(self.engine)

    def create_collection(self, name: str, user_id: int) -> int:
        collection_key = secrets.token_bytes(32)
        with Session(self.engine) as session:
            query = select(User.public_key).where(User.id == user_id)
            public_key = session.execute(query).scalar_one()

            encrypted_key = crypt.asym_encrypt_key(collection_key, public_key)
            query = insert(Collection).values(
                name=name).returning(Collection.id)
            collection_id = session.execute(query).scalar_one()

            query = insert(AccessToCollection).values(
                user_id=user_id, collection_id=collection_id, encrypted_key=encrypted_key, type_id=1)
            session.execute(query)

            session.commit()
            return collection_id

    def create_group(self, user_id: int, title: str, description: str) -> int:
        with Session(self.engine) as session:
            group_private_key, group_public_key = crypt.generate_x25519_keypair()
            try:
                query = insert(Group).values(
                    title=title, description=description, public_key=group_public_key).returning(Group.id)
                group_id = session.execute(query).scalar_one()
            except IntegrityError as error:
                if "unique constraint" in str(error).lower() or "duplicate key" in str(error).lower():
                    raise HTTPException(
                        status_code=409,
                        detail=f'Title "{title}" already exists'
                    )
                else:
                    raise error
            query = select(User.public_key).where(User.id == user_id)
            user_public_key = session.execute(query).scalar_one()
            encrypted_private_key = crypt.asym_encrypt_key(
                group_private_key, user_public_key)
            query = insert(GroupUser).values(
                user_id=user_id, group_id=group_id, role_id=1, encrypted_private_key=encrypted_private_key)
            session.execute(query)
            session.commit()
            return group_id

    def get_user_private_key(self, user_id: int, key: bytes) -> bytes:
        with Session(self.engine) as session:
            query = select(User.encrypted_private_key).where(
                User.id == user_id)
            encrypted_private_key = session.execute(query).scalar_one()
            private_key = crypt.sym_decrypt_key(encrypted_private_key, key)
            return private_key

    def get_collection_key(self, collection_id: int | str, user_id: int, key: bytes) -> bytes:
        with Session(self.engine) as session:
            user_private_key = self.get_user_private_key(user_id, key)
            if not isinstance(collection_id, int):
                query = select(Collection.id).where(
                    Collection.name == collection_id)
                collection_id = session.execute(query).scalar_one()

            query = select(AccessToCollection.encrypted_key).where(
                (AccessToCollection.collection_id == collection_id) & (AccessToCollection.user_id == user_id))
            encrypted_key = session.execute(query).scalar_one_or_none()
            if encrypted_key is not None:
                collection_key = crypt.asym_decrypt_key(
                    encrypted_key, user_private_key)
            else:
                query = select(GroupUser.group_id).where(
                    GroupUser.user_id == user_id)
                groups_result = session.execute(query).all()
                groups = []
                for group in groups_result:
                    groups.append(group[0])
                query = select(AccessToCollection.encrypted_key, AccessToCollection.group_id).where(
                    (AccessToCollection.collection_id == collection_id) & (AccessToCollection.group_id.in_(groups)))
                result = session.execute(query).first()
                if result is not None:
                    encrypted_key = result[0]
                    group_id = result[1]
                    group_private_key = self.get_group_private_key(
                        group_id, user_id, key)
                    collection_key = crypt.asym_decrypt_key(
                        encrypted_key, group_private_key)
                else:
                    query = select(Collection.key).where(
                        (Collection.id == collection_id) & (Collection.key).is_not(None))
                    collection_key = session.execute(query).scalar_one()
            return collection_key

    def get_group_private_key(self, group_id: int, user_id: int, key: bytes) -> bytes:
        with Session(self.engine) as session:
            user_private_key = self.get_user_private_key(user_id, key)
            query = select(GroupUser.encrypted_private_key).where(
                (GroupUser.group_id == group_id) & (GroupUser.user_id == user_id))
            encrypted_private_key = session.execute(query).scalar_one()
            group_private_key = crypt.asym_decrypt_key(
                encrypted_private_key, user_private_key)
            return group_private_key

    def get_user_id(self, username: str) -> int | None:
        with Session(self.engine) as session:
            query = select(User.id).where(User.username == username)
            user_id = session.execute(query).scalar()
            return user_id

    def get_username(self, user_id: int) -> str | None:
        with Session(self.engine) as session:
            query = select(User.username).where(User.id == user_id)
            username = session.execute(query).scalar()
            return username

    def get_collections(self, user_id: int, accessed_to_all: bool = False) -> list[dict]:
        owner = self.get_owner_collections(user_id)
        accessed = self.get_access_collections(user_id)
        group = self.get_group_collections(user_id)
        accessed_to_all_list = []

        if accessed_to_all:
            accessed_to_all_list = self.get_access_to_all_collections(user_id)
        return owner + accessed + group + accessed_to_all_list

    def get_owner_collections(self, user_id: int) -> list[dict]:
        result = []
        with Session(self.engine) as session:
            query = select(AccessToCollection.collection_id, Collection.name, AccessToCollection.type_id, Collection.key).where(
                (AccessToCollection.user_id == user_id) & (Collection.id == AccessToCollection.collection_id) & (AccessToCollection.type_id == 1))
            collections = session.execute(query).all()
            for collection in collections:
                result.append(
                    {'id': collection[0], 'name': collection[1], 'type': 'owner', 'access_type_id': collection[2], 'is_access_all': collection[3] is not None})
            return result

    def get_access_collections(self, user_id: int) -> list[dict]:
        result = []
        with Session(self.engine) as session:
            query = select(AccessToCollection.collection_id, Collection.name, AccessToCollection.type_id).where(
                (AccessToCollection.user_id == user_id) & (Collection.id == AccessToCollection.collection_id) & (AccessToCollection.type_id != 1))
            collections = session.execute(query).all()
            for collection in collections:
                result.append(
                    {'id': collection[0], 'name': collection[1], 'type': 'access', 'access_type_id': collection[2]})
            return result

    def get_group_collections(self, user_id: int) -> list[dict]:
        result = []
        with Session(self.engine) as session:
            query = select(
                AccessToCollection.collection_id,
                Collection.name,
                AccessToCollection.type_id
            ).where(
                (AccessToCollection.group_id.in_(select(GroupUser.group_id).where(GroupUser.user_id == user_id))) &
                (Collection.id == AccessToCollection.collection_id) &
                (Collection.id.not_in(
                    select(AccessToCollection.collection_id).where(
                        AccessToCollection.user_id == user_id
                    )
                ))
            )
            collections = session.execute(query).all()
            for collection in collections:
                result.append(
                    {'id': collection[0], 'name': collection[1], 'type': 'group', 'access_type_id': collection[2]})
            return result

    def get_access_to_all_collections(self, user_id: int) -> list[dict]:
        result = []
        with Session(self.engine) as session:
            query = select(Collection.id, Collection.name).where(
                (Collection.key.is_not(None)) &
                (Collection.id.not_in(
                    select(AccessToCollection.collection_id).where(
                        (AccessToCollection.user_id == user_id) |
                        (AccessToCollection.group_id.in_(
                            select(GroupUser.group_id).where(
                                GroupUser.user_id == user_id)
                        ))
                    )
                ))
            )
            collections = session.execute(query).all()
            for collection in collections:
                result.append(
                    {'id': collection[0], 'name': collection[1], 'type': 'access_to_all', 'access_type_id': 3})
            return result

    def get_specific_access_to_all_collections(self, user_id: int, collection_ids: list[int]) -> list[dict]:
        result = []
        with Session(self.engine) as session:
            query = select(Collection.id, Collection.name).where(
                (Collection.key.is_not(None)) &
                (Collection.id.in_(collection_ids)) &
                (Collection.id.not_in(
                    select(AccessToCollection.collection_id).where(
                        (AccessToCollection.user_id == user_id) |
                        (AccessToCollection.group_id.in_(
                            select(GroupUser.group_id).where(
                                GroupUser.user_id == user_id)
                        ))
                    )
                ))
            )
            collections = session.execute(query).all()
            for collection in collections:
                result.append(
                    {'id': collection[0], 'name': collection[1], 'type': 'access_to_all', 'access_type_id': 3})
            return result

    def get_absolute_access_to_all_collections(self) -> list[dict]:
        result = []
        with Session(self.engine) as session:
            query = select(Collection.id, Collection.name).where(
                Collection.key.is_not(None))
            collections = session.execute(query).all()
            for collection in collections:
                result.append(
                    {'id': collection[0], 'name': collection[1], 'type': 'access_to_all', 'access_type_id': 3})
            return result

    def get_user_public_key(self, user_id: int) -> bytes:
        with Session(self.engine) as session:
            query = select(User.public_key).where(User.id == user_id)
            return session.execute(query).scalar_one()

    def get_group_public_key(self, group_id: int) -> bytes:
        with Session(self.engine) as session:
            query = select(Group.public_key).where(Group.id == group_id)
            return session.execute(query).scalar_one()

    def give_access_user_to_collection(self, collection_id: int, owner_user_id: int, access_user_id: int, access_type_id: int, key: bytes) -> int:
        with Session(self.engine) as session:
            query = select(AccessToCollection.user_id).where(
                (AccessToCollection.user_id == owner_user_id) &
                (AccessToCollection.collection_id == collection_id) &
                (AccessToCollection.type_id == 1) &
                (AccessToCollection.type_id < access_type_id)
            )
            session.execute(query).scalar_one()

            collection_key = self.get_collection_key(
                collection_id, owner_user_id, key)
            user_public_key = self.get_user_public_key(access_user_id)
            collection_encrypted_key = crypt.asym_encrypt_key(
                collection_key, user_public_key)

            query = insert(AccessToCollection).values(collection_id=collection_id, user_id=access_user_id,
                                                      type_id=access_type_id, encrypted_key=collection_encrypted_key).returning(AccessToCollection.id)
            result = session.execute(query).scalar_one()
            session.commit()
            return result

    def give_access_group_to_collection(self, collection_id: int, user_id: int, group_id: int, access_type_id: int, key: bytes) -> int:
        with Session(self.engine) as session:
            query = select(AccessToCollection.user_id).where(
                (AccessToCollection.user_id == user_id) &
                (AccessToCollection.collection_id == collection_id) &
                (AccessToCollection.type_id == 1) &
                (AccessToCollection.type_id < access_type_id)
            )
            session.execute(query).scalar_one()

            collection_key = self.get_collection_key(
                collection_id, user_id, key)
            group_public_key = self.get_group_public_key(group_id)
            collection_encrypted_key = crypt.asym_encrypt_key(
                collection_key, group_public_key)

            query = insert(AccessToCollection).values(collection_id=collection_id, group_id=group_id,
                                                      type_id=access_type_id, encrypted_key=collection_encrypted_key).returning(AccessToCollection.id)
            result = session.execute(query).scalar_one()
            session.commit()
            return result

    def add_user_to_group(self, group_id: int, admin_user_id: int, new_user_id: int, role_id: int, key: bytes):
        with Session(self.engine) as session:
            query = select(GroupUser.user_id).where(
                (GroupUser.user_id == admin_user_id) &
                (GroupUser.group_id == group_id) &
                (GroupUser.role_id < role_id)
            )
            session.execute(query).scalar_one()

            group_private_key = self.get_group_private_key(
                group_id, admin_user_id, key)
            user_public_key = self.get_user_public_key(new_user_id)
            encrypted_group_private_key = crypt.asym_encrypt_key(
                group_private_key, user_public_key)

            try:
                query = insert(GroupUser).values(group_id=group_id, user_id=new_user_id,
                                                 role_id=role_id, encrypted_private_key=encrypted_group_private_key)
                session.execute(query)
            except IntegrityError as error:
                if "unique constraint" in str(error).lower() or "duplicate key" in str(error).lower():
                    raise HTTPException(
                        status_code=409,
                        detail=f'The user is already in the group'
                    )
                else:
                    raise error
            session.commit()

    def delete_user_to_group(self, group_id: int, delete_user_id: int, user_id: int):
        with Session(self.engine) as session:
            query = delete(GroupUser).where(
                (GroupUser.user_id == delete_user_id) &
                (GroupUser.group_id == group_id) &
                ((GroupUser.role_id != 1) | (select(GroupUser.role_id).where(
                    (GroupUser.user_id == user_id) &
                    (GroupUser.group_id == group_id)
                ).scalar_subquery() == 1)) &
                ((GroupUser.role_id > select(GroupUser.role_id).where(
                    (GroupUser.user_id == user_id) &
                    (GroupUser.group_id == group_id)
                )) | (GroupUser.user_id == user_id))
            )
            session.execute(query)
            query = update(Group).where(
                (Group.id == group_id) &
                (~exists(select(1).where(GroupUser.group_id == group_id)))
            ).values(title=func.left(Group.title, 200) + f' | deleted at {datetime.now()}')
            session.execute(query)
            session.commit()

    def get_groups(self, user_id: int) -> list[dict]:
        with Session(self.engine) as session:
            query = select(Group.id, Group.title, Group.description, GroupUser.role_id).where(
                (GroupUser.user_id == user_id) & (GroupUser.group_id == Group.id))
            result = session.execute(query).all()
            groups = []
            for group in result:
                groups.append(
                    {'id': group[0], 'title': group[1], 'description': group[2], 'role_id': group[3]})
            return groups

    def remove_collection(self, collection_id: int, user_id: int):
        with Session(self.engine) as session:
            query = select(Collection.id).where(
                (Collection.id == collection_id) & (AccessToCollection.user_id == user_id) & (AccessToCollection.type_id == 1) & (Collection.id == AccessToCollection.collection_id))
            collection_id = session.execute(query).scalar_one()
            query = delete(AccessToCollection).where(
                AccessToCollection.collection_id == collection_id)
            session.execute(query)
            query = delete(Log).where(Log.collection_id == collection_id)
            session.execute(query)
            query = delete(Collection).where(Collection.id == collection_id)
            session.execute(query)
            session.commit()

    def get_other_users(self, user_id: int) -> list[dict]:
        with Session(self.engine) as session:
            query = select(User.id, User.username).where(User.id != user_id)
            result = session.execute(query).all()
            users = []
            for user in result:
                users.append({'id': user[0], 'username': user[1]})
            return users

    def get_access_to_collection(self, collection_id: int, user_id: int) -> list[dict]:
        with Session(self.engine) as session:
            query = select(
                AccessToCollection.id,
                AccessToCollection.user_id,
                User.username,
                AccessToCollection.group_id,
                Group.title,
                AccessToCollection.type_id,
                AccessType.name,
            ).where(
                (AccessToCollection.collection_id == collection_id) &
                (
                    (AccessToCollection.type_id == 1) |
                    (AccessToCollection.user_id == user_id) |
                    (AccessToCollection.group_id.in_(select(GroupUser.group_id).where(GroupUser.user_id == user_id))) |
                    (AccessToCollection.collection_id.in_(
                        select(AccessToCollection.collection_id).where(
                            (AccessToCollection.user_id == user_id) & (AccessToCollection.type_id == 1))
                    ))
                )
            ).outerjoin(User, AccessToCollection.user_id == User.id).outerjoin(Group, AccessToCollection.group_id == Group.id).outerjoin(AccessType, AccessType.id == AccessToCollection.type_id)
            result = session.execute(query).all()
            list_access = []
            for access in result:
                if access[1] is None:
                    list_access.append(
                        {'id': access[0], 'target_id': access[3], 'target_name': access[4], 'target_type': 'group', 'type_id': access[5], 'type_name': access[6]})
                else:
                    list_access.append(
                        {'id': access[0], 'target_id': access[1], 'target_name': access[2], 'target_type': 'user', 'type_id': access[5], 'type_name': access[6]})
            return list_access

    def delete_access_to_collection(self, access_id: int, user_id: int):
        with Session(self.engine) as session:
            query = delete(AccessToCollection).where(
                (AccessToCollection.id == access_id) &
                (AccessToCollection.type_id != 1) &
                (
                    (AccessToCollection.user_id == user_id) |
                    (AccessToCollection.collection_id.in_(
                        select(AccessToCollection.collection_id).where(
                            (AccessToCollection.user_id == user_id) &
                            (AccessToCollection.type_id == 1)
                        )
                    ))
                )
            )
            session.execute(query)
            session.commit()

    def get_group_users(self, group_id: int, user_id: int) -> list[dict]:
        with Session(self.engine) as session:
            query = select(GroupUser.user_id, User.username, GroupUser.role_id).where(
                (GroupUser.group_id == group_id) &
                (GroupUser.group_id).in_(
                    select(GroupUser.group_id).where(
                        GroupUser.user_id == user_id)
                )
            ).outerjoin(User, GroupUser.user_id == User.id)
            result = session.execute(query).all()
            users = []
            for user in result:
                users.append(
                    {'id': user[0], 'username': user[1], 'role_id': user[2]})
            return users

    def get_access_types(self) -> list[dict]:
        with Session(self.engine) as session:
            query = select(AccessType.id, AccessType.name).where(
                AccessType.id != 1)
            result = session.execute(query).all()
            access_types = []
            for access_type in result:
                access_types.append(
                    {'id': access_type[0], 'name': access_type[1]})
            return access_types

    def transfer_power_to_group(self, group_id: int, owner_user_id: int, user_id: int) -> None:
        with Session(self.engine) as session:
            query = update(GroupUser).where(
                (GroupUser.group_id == group_id) &
                (GroupUser.user_id == owner_user_id) &
                (GroupUser.role_id == 1)
            ).values(role_id=2)
            if session.execute(query).rowcount == 1: # type: ignore[attr-defined]
                query = update(GroupUser).where(
                    (GroupUser.group_id == group_id) &
                    (GroupUser.user_id == user_id)
                ).values(role_id=1)
                session.execute(query)
                session.commit()

    def add_log(self, action: str, status: int, detail: dict | None, user_id: int | None = None, group_id: int | None = None, collection_id: int | None = None) -> None:
        try:
            with Session(self.engine) as session:
                query = insert(Log).values(created_at=datetime.now(), action=action,
                                           status=status, detail=detail, user_id=user_id, group_id=group_id, collection_id=collection_id)
                session.execute(query)
                session.commit()
        except Exception as error:
            with Session(self.engine) as session:
                query = insert(Log).values(created_at=datetime.now(), action='add_log',
                                           status=500, detail={'error': str(error), 'action': action}, user_id=user_id, group_id=group_id)
                session.execute(query)
                session.commit()

    def get_type_access(self, collection_id: int | str, user_id: int):
        with Session(self.engine) as session:
            if not isinstance(collection_id, int):
                query = select(Collection.id).where(
                    Collection.name == collection_id)
                collection_id = session.execute(query).scalar_one()

            all_access_to_collection = self.get_access_to_collection(
                collection_id, user_id)
            collections = self.get_group_collections(user_id)
            for access in all_access_to_collection:
                if access['target_type'] == 'user':
                    if access['target_id'] == user_id:
                        return access['type_id']
            result = list(
                filter(lambda x: x['id'] == collection_id, collections))
            if len(result) > 0:
                return result[0]['access_type_id']
            else:
                query = select(Collection.id).where(
                    (Collection.id == collection_id) &
                    (Collection.key.is_not(None))
                )
                if session.execute(query).scalar():
                    return 3

    def change_role_in_group(self, group_id: int, owner_user_id: int, user_id: int, role_id: int) -> bool:
        with Session(self.engine) as session:
            if role_id != 1:
                query = select(GroupUser.user_id).where(
                    (GroupUser.group_id == group_id) &
                    (GroupUser.user_id == owner_user_id) &
                    (GroupUser.role_id == 1)
                )
                session.execute(query).scalar_one()

                query = update(GroupUser).where(
                    (GroupUser.group_id == group_id) &
                    (GroupUser.user_id == user_id) &
                    (GroupUser.role_id != 1)
                ).values(role_id=role_id)
                session.execute(query)
                session.commit()
                return True
            else:
                return False

    def get_user_info(self, user_id: int) -> dict[str, int | str]:
        with Session(self.engine) as session:
            query = select(User.id, User.username).where(User.id == user_id)
            user = session.execute(query).one()
            query = select(func.count('*')).select_from(AccessToCollection).where(
                (AccessToCollection.user_id == user_id) & (AccessToCollection.type_id == 1))
            count_collections = session.execute(query).scalar_one()
            result = {'id': user.id, 'username': user.username,
                      'count_collections': count_collections}
            return result

    def get_collection_name(self, collection_id: int) -> str:
        with Session(self.engine) as session:
            query = select(Collection.name).where(
                Collection.id == collection_id)
            return session.execute(query).scalar_one()

    def change_access_type(self, access_id: int, user_id: int, access_type_id: int) -> None:
        with Session(self.engine) as session:
            if access_type_id != 1:
                query = update(AccessToCollection).where(
                    (AccessToCollection.id == access_id) &
                    (AccessToCollection.collection_id.in_(
                        select(AccessToCollection.collection_id).where(
                            (AccessToCollection.user_id == user_id) &
                            (AccessToCollection.type_id == 1)
                        )
                    ))
                ).values(type_id=access_type_id)
                session.execute(query)
                session.commit()

    def get_access_info(self, access_id: int) -> dict[str, int]:
        with Session(self.engine) as session:
            query = select(AccessToCollection.user_id, AccessToCollection.group_id).where(
                AccessToCollection.id == access_id)
            result = session.execute(query).one()
            return {'user_id': result.user_id, 'group_id': result.group_id}

    def change_group_info(self, user_id: int, group_id: int, title: str, description: str) -> None:
        with Session(self.engine) as session:
            try:
                query = update(Group).where(
                    (Group.id == group_id) &
                    (Group.id.in_(
                        select(GroupUser.group_id).where(
                            (GroupUser.user_id == user_id) &
                            (GroupUser.role_id <= 2)
                        )
                    ))
                ).values(title=title, description=description)
                session.execute(query)
            except IntegrityError as error:
                if "unique constraint" in str(error).lower() or "duplicate key" in str(error).lower():
                    raise HTTPException(
                        status_code=409,
                        detail=f'Title "{title}" already exists'
                    )
                else:
                    raise error
            session.commit()

    def get_logs(self, user_id: int) -> list[dict]:
        with Session(self.engine) as session:
            query = select(Log.id, Log.created_at, Log.action, Log.status,
                           Log.detail, Log.group_id, Log.collection_id).where(Log.user_id == user_id).order_by(desc(Log.id)).limit(500)
            result = session.execute(query).all()
            logs = []
            for log in result:
                logs.append(
                    {'id': log[0], 'created_at': log[1], 'action': log[2], 'status': log[3], 'detail': log[4], 'group_id': log[5], 'collection_id': log[6]})
            return logs

    def get_history_collection(self, user_id: int, collection_id: int) -> list[dict]:
        with Session(self.engine) as session:
            query = select(
                Log.id, Log.created_at, Log.action, Log.status, Log.detail, Log.group_id, Log.collection_id, User.username,
            ).where(
                (Log.collection_id == collection_id) &
                (Log.collection_id.in_(
                    select(AccessToCollection.collection_id).where(
                        (AccessToCollection.user_id == user_id) &
                        (AccessToCollection.type_id == 1)
                    )
                )) &
                (User.id == Log.user_id)
            ).order_by(desc(Log.id)).limit(500)
            result = session.execute(query).all()
            logs = []
            for log in result:
                logs.append(
                    {'id': log[0], 'created_at': log[1], 'action': log[2], 'status': log[3], 'detail': log[4], 'group_id': log[5], 'collection_id': log[6], 'username': log[7]})
            return logs

    def change_access_to_all(self, user_id: int, collection_id: int, is_access: bool, key: bytes):
        with Session(self.engine) as session:
            if is_access:
                collection_key = self.get_collection_key(
                    collection_id, user_id, key)
                query = update(Collection).where(
                    (Collection.id == collection_id) &
                    (Collection.id == AccessToCollection.collection_id) &
                    (AccessToCollection.user_id == user_id) &
                    (AccessToCollection.type_id == 1)
                ).values(key=collection_key)
            else:
                query = update(Collection).where(
                    (Collection.id == collection_id) &
                    (Collection.id == AccessToCollection.collection_id) &
                    (AccessToCollection.user_id == user_id) &
                    (AccessToCollection.type_id == 1)
                ).values(key=None)
            session.execute(query)
            session.commit()

    def get_status(self) -> dict:
        with Session(self.engine) as session:
            status = {'name': 'postgresql', 'host': config.db_host, 'type': 'database', 'port': 5432}
            try:
                session.execute(select(1))
                return status | {'status': 'active', 'detail': 'Database is active and reachable'}
            except Exception as error:
                return status | {'status': 'failed', 'detail': f'Failed to get status: {str(error)}'}
