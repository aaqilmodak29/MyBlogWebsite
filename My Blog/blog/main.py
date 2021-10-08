from flask import Flask, render_template, redirect, url_for, abort, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from typing import Callable
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'any-string'
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# # CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


class MySQLAlchemy(SQLAlchemy):
    Column: Callable
    String: Callable
    Integer: Callable
    Boolean: Callable
    Text: Callable
    ForeignKey: Callable


db = MySQLAlchemy(app)
Base = declarative_base()


# # CONFIGURE TABLES
# Parent Table
class Users(UserMixin, db.Model, Base):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)

    posts = relationship("BlogPost", back_populates="author")
    # "comment_author" refers to the comment_author property in the Comment class.
    comments = relationship("Comment", back_populates="comment_author")


# Child 1
class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Create Foreign Key, "users.id" the users refers to the table-name of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("Users", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship("Comment", back_populates="parent_post")


# Child 2
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text, nullable=False)

    # "users.id" The users refers to the tablename of the Users class.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # "comments" refers to the comments property in the User class.
    comment_author = relationship("Users", back_populates="comments")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


# db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        error = None
        email = form.email.data
        pwd = form.password.data
        hashed_pwd = generate_password_hash(pwd, method='pbkdf2:sha256', salt_length=8)
        name = form.name.data

        user = Users.query.filter_by(email=email).first()
        if user:
            error = "You have already registered using that email, login instead!"
            return render_template('login.html', error=error, form=LoginForm())
        else:
            new_user = Users(
                email=email,
                password=hashed_pwd,
                name=name
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    error = None
    if form.validate_on_submit():
        email = form.email.data
        pwd = form.password.data

        user = Users.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, pwd):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                error = "Invalid Password"
        else:
            error = "Invalid Email"
    return render_template("login.html", form=form, error=error)


@login_required
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@login_required
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if current_user.is_authenticated:
            user_comment = form.body.data
            new_comment = Comment(
                comment=user_comment,
                author_id=current_user.id,
                post_id=post_id
            )

            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('get_all_posts'))
        else:
            flash("You need to be logged in to leave a comment!")
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, form=form, current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html")


@login_required
@app.route("/contact")
def contact():
    return render_template("contact.html")


def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            admin = current_user.id
        except AttributeError:
            abort(403)
        else:
            if admin == 1:
                return function(*args, **kwargs)
            else:
                return abort(403)

    return wrapper


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
