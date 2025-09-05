from pydantic import BaseModel, Field
from typing import Optional


class UserCreate(BaseModel):
    username: str
    full_name: Optional[str] = None
    password: str
    role: str = "user"


class UserLogin(BaseModel):
    username: str
    password: str
    use_ldap: bool = False


class ServerCreate(BaseModel):
    hostname: str
    ip_address: str
    system_name: Optional[str] = None
    owner: Optional[str] = None
    is_cluster: bool = False
    environment: str = "prod"  # test|stage|prod


class ServerUpdate(ServerCreate):
    pass



