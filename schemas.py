"""
Database Schemas for E-commerce App

Each Pydantic model corresponds to one MongoDB collection.
Collection name is the lowercase of the class name.
"""
from typing import List, Optional, Literal
from pydantic import BaseModel, Field, EmailStr

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr
    password_hash: str = Field(..., description="Hashed password")
    is_admin: bool = False

class Product(BaseModel):
    name: str
    brand: str
    description: str
    price: float = Field(..., ge=0)
    category: Literal["Mobiles", "Laptops", "Accessories", "Fashion"]
    rating: float = Field(4.0, ge=0, le=5)
    images: List[str] = []
    specs: dict = {}
    stock: int = 10

class OrderItem(BaseModel):
    product_id: str
    name: str
    price: float
    quantity: int
    image: Optional[str] = None

class Order(BaseModel):
    user_id: str
    items: List[OrderItem]
    total: float
    name: str
    address: str
    phone: str
    payment_method: Literal["COD", "Card", "UPI"] = "COD"
    status: Literal["placed", "processing", "shipped", "delivered"] = "placed"
