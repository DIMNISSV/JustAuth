import databases
import ormar
import sqlalchemy
from decouple import config

DATABASE_URL = config("DATABASE_URL")
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()


class BaseMeta(ormar.ModelMeta):
    metadata = metadata
    database = database
