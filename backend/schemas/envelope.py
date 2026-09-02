from typing import Generic, TypeVar, Optional, Literal
from pydantic import BaseModel

T = TypeVar("T")


class ApiResponse(BaseModel, Generic[T]):
    """Standardized API response envelope matching team contract."""
    status: Literal["success", "error"]
    data: Optional[T] = None
    error: Optional[str] = None


def success_response(data: T) -> ApiResponse[T]:
    return ApiResponse[T](status="success", data=data, error=None)


def error_response(message: str) -> ApiResponse[None]:
    return ApiResponse[None](status="error", data=None, error=message)
