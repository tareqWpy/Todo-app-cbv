<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/devicons/devicon@latest/devicon.min.css">
<h1 align="center">Todo-App with Class-Bsed-View</h1>
<h3 align="center">This is simple todo-app project with class based view</h3>

<p align="center" style="display:flex; gap:16px; justify-content:center; align-items:center">
<a href="https://www.python.org/" target="_blank"> <img src="https://cdn.jsdelivr.net/gh/devicons/devicon@latest/icons/python/python-original.svg" alt="python" width="80px" height="80px"/> </a>
<a href="https://www.djangoproject.com/" target="_blank"> <img src="https://cdn.jsdelivr.net/gh/devicons/devicon@latest/icons/django/django-plain-wordmark.svg" alt="django" width="80px" height="80px"/> </a>
<a href="https://www.django-rest-framework.org/" target="_blank"> <img src="https://cdn.jsdelivr.net/gh/devicons/devicon@latest/icons/djangorest/djangorest-original-wordmark.svg" alt="djangorest" width="100px" height="100px"/> </a>
<a href="https://www.docker.com/" target="_blank"> <img src="https://cdn.jsdelivr.net/gh/devicons/devicon@latest/icons/docker/docker-original-wordmark.svg" alt="docker" width="100px" height="100px"/> </a>
<a href="https://getbootstrap.com/" target="_blank"> <img src="https://cdn.jsdelivr.net/gh/devicons/devicon@latest/icons/bootstrap/bootstrap-original.svg" alt="bootstrap" width="100px" height="100px"/> </a>
</p>

### Overview

-   [Overview](#overview)
-   [Features](#features)
-   [Setup](#setup)
-   [Getting ready](#getting-ready)
-   [options](#options)
-   [Database schema](#database-schema)
-   [Todo](#todo)
-   [Bugs or Opinion](#bugs-or-opinion)

### Features

-   Bootstrap5
-   Django LTS (4.2)
-   Responsive Design
-   Class Based Views
-   Template Based & API Based
-   User authentication with JWT
-   Email Verification and other features

### Setup

To get this repository, run the following command inside your git enabled terminal

```bash
git clone https://github.com/tareqWpy/Todo-app-cbv.git
```

### Getting ready

#### if you have docker installed, you can use the following commands before starting:

Navigate to your project directory where the docker-compose.yml file exists:

```bash
docker-compose up --build
```

You need to access your backend container's bash:

```bash
docker-compose exec backend bash
```

Then create the database tables:

```bash
python manage.py makemigrations
```

This will create all the migrations file (database migrations) required to run this App.

Now, to apply this migrations run the following command:

```bash
python manage.py migrate
```

For leaving the bash terminal of your backend container:

```bash
exit
```

Then you can read [options](#options) part.

#### if you don't have docker installed, you can use the following commands before starting:

Create an enviroment in order to keep the repo dependencies seperated from your local machine.

```bash
python -m venv venv
```

Make sure to install the dependencies of the project through the requirements.txt file.

```bash
pip install -r requirements.txt
```

Once you have installed django and other packages, go to the cloned repo directory and run the following command:

```bash
python manage.py makemigrations
```

This will create all the migrations file (database migrations) required to run this App.

Now, to apply this migrations run the following command:

```bash
python manage.py migrate
```

### options

Project it self has the user creation form but still in order to use the admin you need to create a super user.you can use the createsuperuser option to make a super user:

```bash
python manage.py createsuperuser
```

And lastly let's make the App run. We just need to start the server now and then we can start using our simple todo App. Start the server by following command:

```bash
python manage.py runserver
```

Once the server is up and running, head over to http://127.0.0.1:8000 for the App.

### Database schema

A simple view of the project model schema.

<p align="center">
<img src="./preview/models-schem.png" alt="database schema" width="300"/>
</p>

### Todo

-   [ ] add heroku config files
-   [ ] leave comments for codes
-   [ ] create a video tutorial or demo
-   [ ] complete the documentation

### Bugs or Opinion

Feel free to let me know if there are any problems or any request you have for this repo.
