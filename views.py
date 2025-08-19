from flask_restful import Resource
from flask import request, jsonify, render_template, flash, redirect, url_for, make_response
from models import db, User, Post, ROLE_USER, ROLE_ADMIN, ROLE_MANAGER
from flask_restful import Api
from flask_jwt_extended import create_access_token, create_refresh_token, JWTManager, get_jwt_identity, get_jwt, get_jti, jwt_required, verify_jwt_in_request
from app import app
from functools import wraps

api = Api(app)
jwt = JWTManager(app)

jwt_blocklist = set()

# Function to check if token has been blocked
@jwt.token_in_blocklist_loader
def check_revoked(jwt_headers, jwt_payload):
    return jwt_payload.get("jti") in jwt_blocklist


# Function to manage Role Based Access (RBAC)
def roles_required(*allowed_roles):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            role = get_jwt().get("role")
            if role not in allowed_roles:
                return {
                    "message": "Insufficient permission to perform that operation"
                }, 401
            return fn(*args, **kwargs)
        return wrapper
    return decorator



class RegisterResource(Resource):
    def post(self):
        data = request.get_json() or {}
        email = data.get("email", "").lower().strip()
        password = data.get("password", "")
        role = data.get("role", None)

        if len(email) < 1 or len(password) < 1:
            return { "message": "Email and password are required" }, 400
        if len(password) < 6:
            return { "message": "Password is too short" }, 400
        if User.query.filter_by(email=email).first():
            return { "message": "Email already registered" }, 400
        
        try:
            user = User(email=email, role=role)
            user.set_password(password)

            db.session.add(user)
            db.session.commit()
            return { "message": "User registered", "data": { "email":email, "role":user.role } }, 201
        except ValueError as ve:
            return { "message": f"{ve}" }, 400


class LoginResource(Resource):
    def post(self):
        data = request.get_json() or {}
        email = data.get("email", "").lower().strip()
        password = data.get("password", "")
        user = User.query.filter_by(email=email).first()

        if not user or not user.check_password(password):
            return { "message": "Invalid Credentials" }, 401
        if not user.is_active:
            return { "message": "User account is inactive" }, 403
        
        claims = { "role" : user.role, "email": user.email, "isActive": user.is_active }
        access_token = create_access_token(identity=user.id, additional_claims=claims)
        refresh_token = create_refresh_token(identity=user.id, additional_claims=claims)

        response = {
                    "message": "Success",
                    "data": {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "email": user.email,
                        "role": user.role
                    }
                }, 200
        
        return response
        

class RefreshResource(Resource):
    @jwt_required(refresh=True)
    def post(self):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user:
            return { "message": "User does not exist" }, 404
        claims = { "role" : user.role, "email": user.email, "isActive": user.is_active }
        access_token = create_access_token(identity=user.id, additional_claims=claims)
        return {
            "access_token": access_token
        }

class LogoutResource(Resource):
    @jwt_required()
    def post(self):
        # headers = request.headers
        # token = headers.get("Authorization").split(" ")[1]
        # jti = get_jti(token)
        jti = get_jwt().get("jti")
        jwt_blocklist.add(jti)
        return { "message": "Logout successful" }


class MeResource(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user:
            return { "message": "user not found" }, 404
        return { 
            "id": user.id, 
            "email": user.email, 
            "role":user.role, 
            "active": user.is_active, 
            "joined": str(user.created_at)
        }


class PostResource(Resource):
      def get(self):
          posts = Post.query.order_by(Post.created_at.desc()).all()
          return {
              "message": "Success",
              "data": {
                  "posts": [{
                      "id": p.id, "title": p.title, 
                      "author_id": p.author_id, 
                      "created_at": p.created_at.isoformat()
                  } for p in posts]
              }
          }

      @roles_required(ROLE_ADMIN, ROLE_MANAGER, ROLE_USER)
      def post(self):
          user_id = get_jwt_identity()
          data = request.get_json() or {}
          title = data.get("title")
          if not title:
              return { "message": "Title of post is not present" }, 422
          post = Post(title=title, author_id=user_id)
          db.session.add(post)
          db.session.commit()
          return {
              "message": "Success",
              "data": {
                  "id": post.id,
                  "title": post.title
              }
          } 

# TODO: 1. Add report resource and only allow manager/admin (show total counts for posts and users, day report was generated)
# TODO: 2. Add users resource and only allow admin (all user data except password)    

api.add_resource(RegisterResource, "/auth/register")
api.add_resource(LoginResource, "/auth/login")
api.add_resource(LogoutResource, "/auth/logout")
api.add_resource(RefreshResource, "/auth/refresh")
api.add_resource(MeResource, "/me")

api.add_resource(PostResource, "/posts")


def ui_login_required(*roles):
    """Protect Jinja routes with JWT and optional role checking."""
    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            try:
                # verify token in cookie
                verify_jwt_in_request(locations=["cookies"])
                claims = get_jwt()
                
                # role-based access check
                if claims.get("role") not in roles:
                    flash("You are not authorized to access this page.", "danger")
                    return redirect(url_for("ui_login"))
                
            except Exception:
                flash("Please log in to access this page.", "warning")
                return redirect(url_for("ui_login"))

            return fn(*args, **kwargs)
        return decorated
    return wrapper

@app.route("/ui/posts/add", methods=["POST", "GET"])
@ui_login_required(ROLE_ADMIN, ROLE_MANAGER, ROLE_USER)
def ui_add_post():
    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content", "No content provided")
        if not content:
            flash("Content of post is not present", category="danger")
            return redirect(url_for("ui_add_post"))
        
        if not title:
            flash("Title of post is not present", category="danger")
            return redirect(url_for("ui_add_post"))
        
        user_id = get_jwt_identity()
        post = Post(title=title, author_id=user_id, content=content)
        db.session.add(post)
        db.session.commit()
        flash("Added post successfully", category="success")
        return redirect(url_for("ui_posts"))
    return render_template("post_add.html", current_user=get_jwt_identity())

@app.route("/ui/posts")
@jwt_required(locations=["cookies"], optional=True)
def ui_posts():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template("post_list.html", posts=posts, current_user=get_jwt_identity())


@app.route("/ui/login", methods=["GET", "POST"])
def ui_login():
    if request.method == "POST":
        email = request.form.get("email").lower().strip()
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()

        if not user or not user.check_password(password):
            flash("Invalid credentials", "danger")
            return redirect(url_for("ui_login"))

        # create tokens
        claims = {"role": user.role}
        access = create_access_token(identity=user.id, additional_claims=claims)

        resp = make_response(redirect(url_for("ui_posts")))
        # set JWT in cookies
        resp.set_cookie("access_token_cookie", access, httponly=True)
        flash("Logged in successfully!", "success")
        return resp

    return render_template("login.html")
