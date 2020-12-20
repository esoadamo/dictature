import sqlite3
import queue

from threading import Thread, Lock, main_thread
from typing import NamedTuple, Tuple, Union, Optional, List, Callable, Dict
from pathlib import Path


class DBCommandSQL(NamedTuple):
    command: str
    data: Tuple


class DBCommandCommit(NamedTuple):
    commit: bool


class DBCommandQuit(NamedTuple):
    quit: bool


DBResult = List[Tuple]

DBCommand = Union[DBCommandCommit, DBCommandSQL, DBCommandQuit]
DBRespond = Optional[Union[Exception, bool, DBResult]]


def is_main_thread_running() -> bool:
    return main_thread().is_alive()


class SQLiteDB:
    """
    Synchronized worker with the SQLite database
    """

    def __init__(self,
                 file_path: Union[str, Path],
                 autoquit_test: Optional[Callable[[], bool]] = is_main_thread_running
                 ) -> None:
        """
        Initialize the static database
        :param file_path: path to the saved file with database
        :param autoquit_test: function called to determine if the database should exit
        by default is the database terminated together with main thread, pass None to disable
        :return: None
        """
        if type(file_path) is str:
            self.memory_db = file_path == ':memory:'
            if not self.memory_db:
                file_path = Path(file_path)
        else:
            self.memory_db = False

        self.exited = False
        self.__queue_in: queue.Queue[DBCommand] = queue.Queue()  # operations to perform
        self.__queue_out: queue.Queue[DBRespond] = queue.Queue()  # data to return
        self.__db_lock = Lock()

        def thread_db_keep_running() -> bool:
            if self.exited:
                # already exited
                return False
            if autoquit_test is None:
                # no test defined, keep running
                return True
            # process all commands and exit if autoquit returns False
            return autoquit_test() or not self.__queue_in.empty()

        def thread_db_connection() -> None:
            """
            This thread runs in background and performs all operations with the database if needed
            Creates new database if not exists yet
            """
            if self.memory_db:
                connection = sqlite3.connect(":memory:")
            else:
                db_dir = file_path.parent
                if not db_dir.exists():
                    db_dir.mkdir(parents=True, mode=0o750)
                connection = sqlite3.connect(f"{file_path.absolute()}")

            while thread_db_keep_running():
                try:
                    command: DBCommand = self.__queue_in.get(timeout=5)
                    try:
                        # the present key determines what time of data this is
                        if type(command) is DBCommandSQL:  # perform SQL query
                            db_respond = list(connection.execute(command.command, command.data))
                        elif type(command) is DBCommandCommit:  # commit the saved data
                            connection.commit()
                            db_respond = True
                        elif type(command) is DBCommandQuit:
                            self.exited = True
                            db_respond = True
                        else:  # not sure what to do, just respond None
                            db_respond = None
                    except Exception as e:
                        db_respond = e
                    # return responded object
                    self.__queue_out.put(db_respond)
                except queue.Empty:
                    pass

            connection.commit()
            self.exited = True

        # start the background thread with database connection
        Thread(target=thread_db_connection).start()

    def execute(self, command: str, data: Tuple = ()) -> DBResult:
        """
        Executes the command on database
        :param command: SQL command to be executed
        :param data: tuple of data that are safely entered into the SQL command to prevent SQL injection
        :return: list of returned rows
        """
        self.__db_lock.acquire()
        self.__queue_in.put(DBCommandSQL(command=command, data=data))
        respond = self.__queue_out.get()
        self.__db_lock.release()
        if isinstance(respond, Exception):
            raise respond
        return respond

    def json(self, command: str, table: str, data: Tuple = ()) -> List[Dict[str, any]]:
        """
        Performs SQL query on table and returns the result as list of dictionaries
        :param command: SQL command to be executed
        :param table: target table of the command. From this table the names of columns are parsed
        :param data: tuple of data that are safely entered into the SQL command to prevent SQL injection
        :return: list of rows, rows are dictionaries where keys are names of columns
        """
        table = table.replace('`', '``')
        columns = [column_data[1] for column_data in self.execute(f"PRAGMA table_info(`{table}`)")]
        records = self.execute(command, data)
        return [{columns[i]: value for i, value in enumerate(record)} for record in records]

    def commit(self) -> bool:
        """
        Commits the databse to the disc
        :return: None
        """
        self.__db_lock.acquire()
        self.__queue_in.put(DBCommandCommit(commit=True))
        respond = self.__queue_out.get()
        self.__db_lock.release()
        if isinstance(respond, Exception):
            raise respond
        return respond

    def quit(self) -> bool:
        """
        End the database connection
        :return: None
        """
        self.__db_lock.acquire()
        self.__queue_in.put(DBCommandQuit(quit=True))
        respond = self.__queue_out.get()
        self.__db_lock.release()
        if isinstance(respond, Exception):
            raise respond
        return respond
