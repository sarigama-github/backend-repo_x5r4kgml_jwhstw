import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr
from bson.objectid import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Product as ProductSchema, Order as OrderSchema

app = FastAPI(title="E-commerce Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------- Utils -----------------------
JWT_SECRET = os.getenv("JWT_SECRET", "devsecret")
JWT_ALGO = "HS256"
security = HTTPBearer()


def serialize_doc(doc):
    if not doc:
        return doc
    doc = dict(doc)
    _id = doc.get("_id")
    if isinstance(_id, ObjectId):
        doc["id"] = str(_id)
        del doc["_id"]
    # convert datetimes
    for k, v in list(doc.items()):
        if isinstance(v, datetime):
            doc[k] = v.isoformat()
    return doc


def hash_password(password: str) -> str:
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()


def create_token(payload: dict) -> str:
    exp = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode = {**payload, "exp": exp}
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGO)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)
    user_id = payload.get("id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return serialize_doc(user)


# ----------------------- Models -----------------------
class SignupBody(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginBody(BaseModel):
    email: EmailStr
    password: str


class ProductCreateBody(ProductSchema):
    pass


class ProductUpdateBody(BaseModel):
    name: Optional[str] = None
    brand: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    category: Optional[str] = None
    rating: Optional[float] = None
    images: Optional[List[str]] = None
    specs: Optional[dict] = None
    stock: Optional[int] = None


class OrderCreateBody(OrderSchema):
    pass


# ----------------------- Health -----------------------
@app.get("/")
def root():
    return {"message": "E-commerce API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": [],
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected & Working"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()[:10]
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# ----------------------- Auth -----------------------
@app.post("/auth/signup")
def signup(body: SignupBody):
    existing = db["user"].find_one({"email": body.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = UserSchema(
        name=body.name,
        email=body.email,
        password_hash=hash_password(body.password),
        is_admin=False,
    )
    user_id = create_document("user", user)
    token = create_token({"id": user_id, "email": body.email, "is_admin": False})
    return {"token": token, "user": {"id": user_id, "name": body.name, "email": body.email, "is_admin": False}}


@app.post("/auth/login")
def login(body: LoginBody):
    user = db["user"].find_one({"email": body.email})
    if not user or user.get("password_hash") != hash_password(body.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    suser = serialize_doc(user)
    token = create_token({"id": suser["id"], "email": suser["email"], "is_admin": suser.get("is_admin", False)})
    return {"token": token, "user": {"id": suser["id"], "name": suser["name"], "email": suser["email"], "is_admin": suser.get("is_admin", False)}}


# ----------------------- Products -----------------------
@app.get("/products")
def list_products(q: Optional[str] = None, category: Optional[str] = None):
    filt = {}
    if q:
        filt["name"] = {"$regex": q, "$options": "i"}
    if category:
        filt["category"] = category
    items = db["product"].find(filt).limit(100)
    return [serialize_doc(i) for i in items]


@app.get("/products/{product_id}")
def get_product(product_id: str):
    item = db["product"].find_one({"_id": ObjectId(product_id)})
    if not item:
        raise HTTPException(status_code=404, detail="Product not found")
    return serialize_doc(item)


@app.post("/products")
def create_product(body: ProductCreateBody, user=Depends(get_current_user)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    pid = create_document("product", body)
    return {"id": pid}


@app.put("/products/{product_id}")
def update_product(product_id: str, body: ProductUpdateBody, user=Depends(get_current_user)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    update = {k: v for k, v in body.model_dump(exclude_none=True).items()}
    update["updated_at"] = datetime.now(timezone.utc)
    res = db["product"].update_one({"_id": ObjectId(product_id)}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"ok": True}


@app.delete("/products/{product_id}")
def delete_product(product_id: str, user=Depends(get_current_user)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    res = db["product"].delete_one({"_id": ObjectId(product_id)})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"ok": True}


# ----------------------- Orders -----------------------
@app.post("/orders")
def create_order(body: OrderCreateBody, user=Depends(get_current_user)):
    if user["id"] != body.user_id and not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Not allowed")
    oid = create_document("order", body)
    return {"id": oid}


# ----------------------- Admin -----------------------
@app.get("/admin/stats")
def admin_stats(user=Depends(get_current_user)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    return {
        "users": db["user"].count_documents({}),
        "products": db["product"].count_documents({}),
        "orders": db["order"].count_documents({}),
    }


# ----------------------- Seed Demo Data -----------------------
DEMO_PRODUCTS = [
    {
        "name": "Pixel 7A",
        "brand": "Google",
        "description": "Powerful camera and smooth Android experience.",
        "price": 34999,
        "category": "Mobiles",
        "rating": 4.4,
        "images": [
            "https://images.unsplash.com/photo-1511707171634-5f897ff02aa9",
        ],
        "specs": {"storage": "128GB", "ram": "8GB"},
        "stock": 25,
    },
    {
        "name": "iPhone 14",
        "brand": "Apple",
        "description": "A15 Bionic with stunning display.",
        "price": 69999,
        "category": "Mobiles",
        "rating": 4.6,
        "images": [
            "https://images.unsplash.com/photo-1603899123335-4a9d94dfbd89",
        ],
        "specs": {"storage": "128GB", "ram": "6GB"},
        "stock": 15,
    },
    {
        "name": "ThinkPad X1",
        "brand": "Lenovo",
        "description": "Business-class laptop with legendary keyboard.",
        "price": 119999,
        "category": "Laptops",
        "rating": 4.5,
        "images": [
            "https://images.unsplash.com/photo-1517336714731-489689fd1ca8",
        ],
        "specs": {"cpu": "i7", "ram": "16GB", "storage": "512GB SSD"},
        "stock": 10,
    },
    {
        "name": "MacBook Air M2",
        "brand": "Apple",
        "description": "Ultra portable with M2 performance.",
        "price": 124999,
        "category": "Laptops",
        "rating": 4.8,
        "images": [
            "https://images.unsplash.com/photo-1517336714731-489689fd1ca8",
        ],
        "specs": {"ram": "8GB", "storage": "256GB SSD"},
        "stock": 12,
    },
    {
        "name": "Noise Cancelling Headphones",
        "brand": "Sony",
        "description": "Immerse in music with ANC.",
        "price": 19999,
        "category": "Accessories",
        "rating": 4.7,
        "images": [
            "https://images.unsplash.com/photo-1518443248587-30bdc8f94f04",
        ],
        "specs": {"battery": "30h"},
        "stock": 40,
    },
    {
        "name": "Mechanical Keyboard",
        "brand": "Keychron",
        "description": "Hot-swappable RGB keyboard.",
        "price": 7999,
        "category": "Accessories",
        "rating": 4.3,
        "images": [
            "https://images.unsplash.com/photo-1516382799247-87df95d790b5",
        ],
        "specs": {"switches": "Gateron"},
        "stock": 30,
    },
    {
        "name": "Casual Sneakers",
        "brand": "Nike",
        "description": "Comfortable everyday wear.",
        "price": 4999,
        "category": "Fashion",
        "rating": 4.2,
        "images": [
            "https://images.unsplash.com/photo-1525966222134-fcfa99b8ae77",
        ],
        "specs": {"size": "7-11"},
        "stock": 50,
    },
    {
        "name": "Smartwatch",
        "brand": "Amazfit",
        "description": "Track fitness and notifications.",
        "price": 6999,
        "category": "Accessories",
        "rating": 4.1,
        "images": [
            "https://images.unsplash.com/photo-1512086734732-172b66a17c72",
        ],
        "specs": {"battery": "10 days"},
        "stock": 35,
    },
]


@app.post("/seed")
def seed():
    if db["product"].count_documents({}) > 0:
        return {"seeded": False, "message": "Products already exist"}
    for p in DEMO_PRODUCTS:
        prod = ProductSchema(**p)
        create_document("product", prod)
    # create admin user if none
    if db["user"].count_documents({"is_admin": True}) == 0:
        admin = UserSchema(name="Admin", email="admin@shop.com", password_hash=hash_password("admin123"), is_admin=True)
        create_document("user", admin)
    return {"seeded": True, "products": db["product"].count_documents({})}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
