import io
import posixpath
from typing import Iterable

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    raise ImportError('Requires: pip install boto3')

from .mock import DictatureTableMock, DictatureBackendMock, Value, ValueMode, ValueSerializer, ValueSerializerMode


class DictatureBackendS3(DictatureBackendMock):
    def __init__(
            self,
            bucket_name: str,
            aws_access_key_id: str = None,
            aws_secret_access_key: str = None,
            region_name: str = None,
            endpoint_url: str = None,
            dir_prefix: str = 'db_',
            item_prefix: str = 'item_'
    ) -> None:
        """
        Initialize S3 backend

        :param bucket_name: S3 bucket name
        :param aws_access_key_id: AWS access key ID
        :param aws_secret_access_key: AWS secret access key
        :param region_name: AWS region name
        :param endpoint_url: Custom endpoint URL for alternative S3-compatible storage (e.g., MinIO)
        :param dir_prefix: Prefix for table directories
        :param item_prefix: Prefix for item files
        """
        self.__s3 = boto3.resource(
            's3',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name,
            endpoint_url=endpoint_url
        )
        self.__bucket = self.__s3.Bucket(bucket_name)
        self.__bucket_name = bucket_name
        self.__dir_prefix = dir_prefix
        self.__item_prefix = item_prefix

    def keys(self) -> Iterable[str]:
        """
        Get all table names in the S3 bucket
        """
        # Group objects by their "directory" prefix
        prefixes = set()
        for obj in self.__bucket.objects.filter(Prefix=self.__dir_prefix):
            key = obj.key
            parts = key.split('/')
            if len(parts) > 1 and parts[0].startswith(self.__dir_prefix):
                prefixes.add(parts[0])

        for prefix in prefixes:
            table_name_encoded = prefix[len(self.__dir_prefix):]
            # noinspection PyProtectedMember
            yield DictatureTableS3._filename_decode(table_name_encoded, suffix='')

    def table(self, name: str) -> 'DictatureTableMock':
        return DictatureTableS3(
            self.__s3,
            self.__bucket_name,
            name,
            self.__dir_prefix,
            self.__item_prefix
        )


class DictatureTableS3(DictatureTableMock):
    def __init__(
            self,
            s3_resource,
            bucket_name: str,
            name: str,
            db_prefix: str,
            prefix: str
    ) -> None:
        self.__s3 = s3_resource
        self.__bucket = self.__s3.Bucket(bucket_name)
        self.__bucket_name = bucket_name
        self.__encoded_name = self._filename_encode(name, suffix='')
        self.__path = f"{db_prefix}{self.__encoded_name}/"
        self.__prefix = prefix
        self.__name_serializer = ValueSerializer(mode=ValueSerializerMode.filename_only)
        self.__value_serializer = ValueSerializer(mode=ValueSerializerMode.any_string)

    def keys(self) -> Iterable[str]:
        try:
            for obj in self.__bucket.objects.filter(Prefix=self.__path):
                key = obj.key
                filename = posixpath.basename(key)
                if filename.startswith(self.__prefix):
                    item_name_encoded = filename[len(self.__prefix):]
                    yield self._filename_decode(item_name_encoded, suffix='.txt')
        except ClientError:
            pass  # Return empty generator if bucket doesn't exist or other error

    def drop(self) -> None:
        """
        Delete all objects in this table's directory
        """
        try:
            self.__bucket.objects.filter(Prefix=self.__path).delete()
        except ClientError:
            pass  # Ignore if objects don't exist or other error

    def create(self) -> None:
        """
        S3 doesn't need explicit directory creation, but we can create a marker file
        to indicate the table's existence if it doesn't already have items
        """
        try:
            # Check if the "directory" exists by looking for any objects with this prefix
            objects = list(self.__bucket.objects.filter(Prefix=self.__path).limit(1))
            if not objects:
                # Create an empty marker object to represent the directory
                self.__bucket.put_object(Key=f"{self.__path}.keep")
        except ClientError:
            # If bucket doesn't exist, this will fail, but that's expected
            pass

    def set(self, item: str, value: Value) -> None:
        item_path = self.__item_path(item)
        save_data: str = self.__value_serializer.serialize(value)
        data_bytes = save_data.encode('utf-8')

        with io.BytesIO(data_bytes) as buffer:
            self.__bucket.upload_fileobj(buffer, item_path)

    def get(self, item: str) -> Value:
        item_path = self.__item_path(item)
        buffer = io.BytesIO()
        try:
            self.__bucket.download_fileobj(item_path, buffer)
            buffer.seek(0)
            save_data = buffer.read().decode('utf-8')
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                raise KeyError(item)
            raise  # Re-raise for other errors
        return self.__value_serializer.deserialize(save_data)

    def delete(self, item: str) -> None:
        """
        Delete the item from S3
        """
        item_path = self.__item_path(item)
        try:
            self.__s3.Object(self.__bucket_name, item_path).delete()
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchKey':
                raise  # Only ignore "not found" errors

    def __item_path(self, item: str) -> str:
        encoded_item_name = self.__prefix + self._filename_encode(item, suffix='.txt')
        full_path = f"{self.__path}{encoded_item_name}"
        return full_path

    @staticmethod
    def _filename_encode(name: str, suffix: str = '.txt') -> str:
        return ValueSerializer(mode=ValueSerializerMode.filename_only).serialize(Value(
            value=name,
            mode=ValueMode.string.value
        )) + suffix

    @staticmethod
    def _filename_decode(name: str, suffix: str = '.txt') -> str:
        if suffix and name.endswith(suffix):
            name = name[:-len(suffix)]
        return ValueSerializer(mode=ValueSerializerMode.filename_only).deserialize(name).value
