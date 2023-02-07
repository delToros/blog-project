# from sqlite3 import IntegrityError

from flask import Flask, render_template, redirect, url_for, flash, request, abort, current_app
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date

from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, Session, session
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar


from functools import wraps



app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(
    app,
    size=100,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None,
)

##CONNECT TO DB

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


## Login Manager
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    # return Session.get(entity=User, ident=user_id)
    return User.query.get(int(user_id))
    # return db.get_or_404(User, user_id)


##CONFIGURE TABLES

# # Это моя проба пера
# class User(UserMixin, db.Model):
#     __tablename__ = "users"
#     id = mapped_column(db.Integer, primary_key=True)
#     name = db.Column(db.String(250), nullable=False)
#     email = db.Column(db.String(250), unique=True, nullable=False)
#     password = db.Column(db.String(250), nullable=False)
#     posts = db.relationship('BlogPost', back_populates='author')
#
#
# class BlogPost(db.Model):
#     __tablename__ = "blog_posts"
#     id = mapped_column(db.Integer, primary_key=True)
#     author_id = mapped_column(db.Integer, ForeignKey('users.id'))
#     author = relationship("User", back_populates="posts")
#     title = db.Column(db.String(250), unique=True, nullable=False)
#     subtitle = db.Column(db.String(250), nullable=False)
#     date = db.Column(db.String(250), nullable=False)
#     body = db.Column(db.Text, nullable=False)
#     img_url = db.Column(db.String(250), nullable=False)

## Это код анжелы
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates='comment_author')
    def get(self):
        return str(self.user_id)

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates='parent_post')

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


# with app.app_context():
#     db.create_all()



# admin decorator
def admin_only(function):
    @wraps(function)
    def wrapper_function():
        if not current_user.is_authenticated or current_user.id != 1:
            return current_app.login_manager.unauthorized()
        else:
            return function()
    return wrapper_function

# def admin_only(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         #If id is not 1 then return abort with 403 error
#         if current_user.id != 1:
#             return abort(403)
#         #Otherwise continue with the route function
#         return f(*args, **kwargs)
#     return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    comment_form = CommentForm()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, current_user=current_user, c_form=comment_form)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        password = request.form.get('password')
        new_user = User(
            name = request.form.get('name'),
            email = request.form.get('email'),
            password = generate_password_hash(password=password, method='pbkdf2:sha256', salt_length=16)
        )
        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            flash('User already exists, please log in')
            return redirect(url_for('login'))

        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        try:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Wrong password, stupid')
                return redirect(url_for('login'))
        except AttributeError:
            flash('No such email in db')
            return redirect(url_for('login'))
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    all_comments = Comment.query.all()
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('You should authorize to post comment')
            return redirect(url_for('login'))
        new_comment = Comment(
            text=comment_form.body.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, c_form=comment_form, current_user=current_user, comments=all_comments)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")

def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=['POST', 'GET'])
# @login_required
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
    return render_template("make-post.html", form=form, current_user=current_user, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>")
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
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
