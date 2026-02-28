from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List
from sqlalchemy import create_engine, Column, Integer, String, Date, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import logging
from logging.config import dictConfig
import os
from passlib.context import CryptContext

# Logging configuration
dictConfig({
    'version': 1,
    'formatters': {
        'default': {
            'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',
            'formatter': 'default'
        }
    },
    'root': {
        'level': 'DEBUG',
        'handlers': ['console']
    }
})

# Database configuration
SQLALCHEMY_DATABASE_URL = 'sqlite:///todo.db'
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Pydantic models
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    lists = relationship('List', back_populates='user')

class List(Base):
    __tablename__ = 'lists'
    id = Column(Integer, primary_key=True)
    title = Column(String, index=True)
    description = Column(String)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship('User', back_populates='lists')
    tasks = relationship('Task', back_populates='list')

class Task(Base):
    __tablename__ = 'tasks'
    id = Column(Integer, primary_key=True)
    title = Column(String, index=True)
    description = Column(String)
    due_date = Column(Date)
    completed = Column(Boolean, default=False)
    list_id = Column(Integer, ForeignKey('lists.id'))
    list = relationship('List', back_populates='tasks')
    tags = relationship('Tag', secondary='task_tags', back_populates='tasks')
    reminders = relationship('Reminder', back_populates='task')

class Tag(Base):
    __tablename__ = 'tags'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, index=True)
    tasks = relationship('Task', secondary='task_tags', back_populates='tags')

class Reminder(Base):
    __tablename__ = 'reminders'
    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, ForeignKey('tasks.id'))
    reminder_date = Column(Date)
    task = relationship('Task', back_populates='reminders')

Base.metadata.create_all(bind=engine)

# FastAPI app
app = FastAPI()

# OAuth2 configuration
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='login')

# Password hashing
pwd_context = CryptContext(schemes=['bcrypt'], default='bcrypt')

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Routes
@app.post('/users', response_model=User)
def create_user(user: User):
    db = next(get_db())
    db_user = User(username=user.username, email=user.email, password=pwd_context.hash(user.password))
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post('/users/login', response_model=dict)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = next(get_db())
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not pwd_context.verify(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid username or password')
    return {'access_token': user.username, 'token_type': 'bearer'}

@app.get('/users/me', response_model=User)
def get_current_user(token: str = Depends(oauth2_scheme)):
    db = next(get_db())
    user = db.query(User).filter(User.username == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    return user

@app.post('/lists', response_model=List)
def create_list(list: List, token: str = Depends(oauth2_scheme)):
    db = next(get_db())
    user = db.query(User).filter(User.username == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    db_list = List(title=list.title, description=list.description, user_id=user.id)
    db.add(db_list)
    db.commit()
    db.refresh(db_list)
    return db_list

@app.get('/lists', response_model=List)
def get_lists(token: str = Depends(oauth2_scheme)):
    db = next(get_db())
    user = db.query(User).filter(User.username == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    lists = db.query(List).filter(List.user_id == user.id).all()
    return lists

@app.get('/lists/{list_id}', response_model=List)
def get_list(list_id: int, token: str = Depends(oauth2_scheme)):
    db = next(get_db())
    user = db.query(User).filter(User.username == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    list = db.query(List).filter(List.id == list_id, List.user_id == user.id).first()
    if not list:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='List not found')
    return list

@app.put('/lists/{list_id}', response_model=List)
def update_list(list_id: int, list: List, token: str = Depends(oauth2_scheme)):
    db = next(get_db())
    user = db.query(User).filter(User.username == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    db_list = db.query(List).filter(List.id == list_id, List.user_id == user.id).first()
    if not db_list:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='List not found')
    db_list.title = list.title
    db_list.description = list.description
    db.commit()
    db.refresh(db_list)
    return db_list

@app.delete('/lists/{list_id}')
def delete_list(list_id: int, token: str = Depends(oauth2_scheme)):
    db = next(get_db())
    user = db.query(User).filter(User.username == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    list = db.query(List).filter(List.id == list_id, List.user_id == user.id).first()
    if not list:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='List not found')
    db.delete(list)
    db.commit()
    return {'message': 'List deleted successfully'}

@app.post('/lists/{list_id}/tasks', response_model=Task)
def create_task(list_id: int, task: Task, token: str = Depends(oauth2_scheme)):
    db = next(get_db())
    user = db.query(User).filter(User.username == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    list = db.query(List).filter(List.id == list_id, List.user_id == user.id).first()
    if not list:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='List not found')
    db_task = Task(title=task.title, description=task.description, due_date=task.due_date, list_id=list_id)
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task

@app.get('/lists/{list_id}/tasks', response_model=List[Task])
def get_tasks(list_id: int, token: str = Depends(oauth2_scheme)):
    db = next(get_db())
    user = db.query(User).filter(User.username == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    list = db.query(List).filter(List.id == list_id, List.user_id == user.id).first()
    if not list:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='List not found')
    tasks = db.query(Task).filter(Task.list_id == list_id).all()
    return tasks

@app.get('/tasks/{task_id}', response_model=Task)
def get_task(task_id: int, token: str = Depends(oauth2_scheme)):
    db = next(get_db())
    user = db.query(User).filter(User.username == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Task not found')
    return task

@app.put('/tasks/{task_id}', response_model=Task)
def update_task(task_id: int, task: Task, token: str = Depends(oauth2_scheme)):
    db = next(get_db())
    user = db.query(User).filter(User.username == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    db_task = db.query(Task).filter(Task.id == task_id).first()
    if not db_task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Task not found')
    db_task.title = task.title
    db_task.description = task.description
    db_task.due_date = task.due_date
    db.commit()
    db.refresh(db_task)
    return db_task

@app.delete('/tasks/{task_id}')
def delete_task(task_id: int, token: str = Depends(oauth2_scheme)):
    db = next(get_db())
    user = db.query(User).filter(User.username == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Task not found')
    db.delete(task)
    db.commit()
    return {'message': 'Task deleted successfully'}

@app.post('/tasks/{task_id}/tags', response_model=Tag)
def add_tag(task_id: int, tag: Tag, token: str = Depends(oauth2_scheme)):
    db = next(get_db())
    user = db.query(User).filter(User.username == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Task not found')
    db_tag = db.query(Tag).filter(Tag.name == tag.name).first()
    if not db_tag:
        db_tag = Tag(name=tag.name)
        db.add(db_tag)
        db.commit()
        db.refresh(db_tag)
    task.tags.append(db_tag)
    db.commit()
    return db_tag

@app.get('/tasks/{task_id}/tags', response_model=List[Tag])
def get_tags(task_id: int, token: str = Depends(oauth2_scheme)):
    db = next(get_db())
    user = db.query(User).filter(User.username == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Task not found')
    return task.tags

@app.delete('/tasks/{task_id}/tags/{tag_id}')
def remove_tag(task_id: int, tag_id: int, token: str = Depends(oauth2_scheme)):
    db = next(get_db())
    user = db.query(User).filter(User.username == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Task not found')
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Tag not found')
    task.tags.remove(tag)
    db.commit()
    return {'message': 'Tag removed successfully'}

@app.post('/tasks/{task_id}/reminders', response_model=Reminder)
def add_reminder(task_id: int, reminder: Reminder, token: str = Depends(oauth2_scheme)):
    db = next(get_db())
    user = db.query(User).filter(User.username == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Task not found')
    db_reminder = Reminder(task_id=task_id, reminder_date=reminder.reminder_date)
    db.add(db_reminder)
    db.commit()
    db.refresh(db_reminder)
    return db_reminder

@app.get('/tasks/{task_id}/reminders', response_model=List[Reminder])
def get_reminders(task_id: int, token: str = Depends(oauth2_scheme)):
    db = next(get_db())
    user = db.query(User).filter(User.username == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Task not found')
    return task.reminders

@app.delete('/tasks/{task_id}/reminders/{reminder_id}')
def remove_reminder(task_id: int, reminder_id: int, token: str = Depends(oauth2_scheme)):
    db = next(get_db())
    user = db.query(User).filter(User.username == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Task not found')
    reminder = db.query(Reminder).filter(Reminder.id == reminder_id).first()
    if not reminder:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Reminder not found')
    db.delete(reminder)
    db.commit()
    return {'message': 'Reminder removed successfully'}

# CORS configuration
from fastapi.middleware.cors import CORSMiddleware

origins = [
    "http://localhost:3000",
    "http://localhost:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
