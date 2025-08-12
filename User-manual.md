
# Network Scanner Web App

A full-stack web application to scan network ports using **Nmap**, with a **React frontend**, **Django REST API backend**, **Nginx** and **PostgreSQL** database.

---

## Features

- User authentication using JWT (Register / Login)
- Start and monitor network port scans using Nmap
- View detailed scan results and activity logs
- Responsive and modern UI built with React & MUI

---

## Tech Stack

| Layer      | Technology         |
|------------|--------------------|
| Frontend   | React, Axios, MUI  |
| Backend    | Django REST, JWT   |
| Database   | PostgreSQL         |
| Web server           | Nginx   |
| Scanner    | Nmap (via system)  |
| Infra      | Bare-metal / Linux |

---

## Requirements (By running setup.sh, all required dependencies will be installed automatically.)

Make sure these are installed on your Linux system (e.g., Ubuntu 22.04): 


- Python 3.10+
- pip
- Node.js (v18 recommended)
- npm
- PostgreSQL
- Nmap
- Nginx

---

## Setup Instructions

### 1. Clone the project

```
git clone https://github.com/mehdismi/network_scanner.git
cd network_scanner
```

## Configuration: Environment variables for frontend
Create a file named .env in network_scanner/netscan-frontend/:
```
REACT_APP_API_BASE=http://<your_server_ip>:8000
```
Replace <your_server_ip> with the actual IP or hostname.

### 2. Run the installation script
```
chmod +x setup.sh
./setup.sh
```

This script will:

- Install required packages

- Set up PostgreSQL user and database

- Create Python virtual environment

- Install backend dependencies

- Run Django migrations

- Install frontend dependencies

- Start both backend and frontend servers


## Access the App
| Service    | URL                              |
|------------|----------------------------------|
| Frontend   | http://<your_server_ip>:8080    |
| Backend    | http://<your_server_ip>:8000     |

## Creating a Superuser
If you want admin access to Django admin panel:
```
cd network_scanner
source venv/bin/activate
python manage.py createsuperuser
```

## Security Note

This setup is intended for development or local deployment. For production:

- Disable DEBUG=True in settings.py
- Use secure database credentials
- Add proper domains to ALLOWED_HOSTS
- Use HTTP and reverse proxy like NGINX

## Author & Support

Developed by Mahdi Salmani

GitHub: https://github.com/mehdismi/

Email: Mohammad.salmani@oulu.fi



## License
MIT License – feel free to use and contribute!






