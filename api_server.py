import docker

from typing import Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel


app = FastAPI(
    title="Mailserver Configurator API"
)


class DeleteUserModel(BaseModel):
    username: str

class UserModelUpdate(DeleteUserModel):
    password: str

class UserModel(UserModelUpdate):
    alias: Optional[str] = None


# Get the Docker client
client = docker.from_env()

# Find the mailserver container
# TODO: pass this as an environment variable or configuration
containers = client.containers.list(filters={"ancestor": "docker.io/mailserver/docker-mailserver:latest"})
container = containers[0] if containers else None


@app.get(
    "/users", 
    summary="List users", 
    description="Lists all registered users in the mail server.",
    responses={
        status.HTTP_200_OK: {"description": "A list of registered users."},
        status.HTTP_404_NOT_FOUND: {"description": "Mailserver container not found."},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Failed to list users."}
    }
)
async def list_users(quotas: bool = False, filter_by: Optional[str] = "*"):
    if not container:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mailserver container not found.")

    if not filter_by:
        filter_by = "*"
    
    # Execute the command to list users inside the container
    if quotas:
        command = ["setup", "email", "list"]
    else:
        command = ["doveadm", "user", filter_by, "list"]
    exit_code, output = container.exec_run(command)

    if exit_code == 0:
        users = output.decode('utf-8').strip().split('\n\n' if quotas else '\n')
        return users
    else:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to list users.")


@app.post(
    "/register", 
    summary="Register a user", 
    description="Registers a new user for the mail server.",
    responses={
        status.HTTP_200_OK: {"description": "User already exists."},
        status.HTTP_201_CREATED: {"description": "User created successfully."},
        status.HTTP_404_NOT_FOUND: {"description": "Mailserver container not found."},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Failed to create user."}
    }
)
async def register_user(user: UserModel):
    username = user.username
    password = user.password
    alias = user.alias

    if not container:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mailserver container not found.")

    # Execute the registration command inside the container
    exit_code, output = container.exec_run(
        ["setup", "email", "add", username, password]
    )

    if exit_code == 0:
        if alias:
            # Add alias if provided
            alias_command = ["setup", "alias", "add", alias, username]
            alias_exit_code, alias_output = container.exec_run(alias_command)
            if alias_exit_code != 0:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"User {username} created but failed to add alias {alias}: {alias_output.decode('utf-8')}")
        return JSONResponse(status_code=status.HTTP_201_CREATED, content=f"User {username} created successfully.")
    else:
        if "already exists" in output.decode('utf-8'):
            return JSONResponse(status_code=status.HTTP_200_OK, content=f"User {username} already exists. Skipping creation.")
        else:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to create user {username}: {output.decode('utf-8')}")
        

@app.put(
    "/update-password",
    summary="Update user password",
    description="Updates the password for an existing user in the mail server.",
    responses={
        status.HTTP_200_OK: {"description": "Password updated successfully."},
        status.HTTP_404_NOT_FOUND: {"description": "Mailserver container not found."},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Failed to update password."}
    }
)
async def update_password(user: UserModelUpdate):
    username = user.username
    password = user.password

    if not container:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mailserver container not found.")

    # Execute the password update command inside the container
    exit_code, output = container.exec_run(
        ["setup", "email", "update", username, password]
    )

    if exit_code == 0:
        return JSONResponse(status_code=status.HTTP_200_OK, content=f"Password for user {username} updated successfully.")
    else:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to update password for user {username}: {output.decode('utf-8')}")


@app.delete(
    "/delete", 
    summary="Delete a user", 
    description="Deletes an existing user from the mail server.",
    responses={
        status.HTTP_200_OK: {"description": "User deleted successfully."},
        status.HTTP_404_NOT_FOUND: {"description": "Mailserver container not found."},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Failed to delete user."}
    }
)
async def delete_user(delete_user: DeleteUserModel):
    username = delete_user.username
    if not container:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mailserver container not found.")
    
    # Prepare the command to delete the user
    command = ["setup", "email", "del", "-y", username]

    # Execute the deletion command inside the container
    exit_code, output = container.exec_run(command)

    if exit_code == 0:
        return JSONResponse(status_code=status.HTTP_200_OK, content=f"User {username} deleted successfully.")
    else:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete user {username}: {output.decode('utf-8')}")
