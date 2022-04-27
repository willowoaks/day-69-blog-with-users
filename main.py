import sqlalchemy.exc
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user, confirm_login
from forms import CreatePostForm, CreateUserForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(user_id)
    return user


def login_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#CONFIGURE TABLES


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="blog")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.String(300))
    blog_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    blog = relationship("BlogPost", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="comments")


db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    if current_user.is_authenticated:
        return render_template("index.html", all_posts=posts, logged_in=True, user_id=current_user.id)
    else:
        return render_template("index.html", all_posts=posts, logged_in=False, user_id=0)



@app.route('/register', methods=["GET", "POST"])
def register():
    form = CreateUserForm()
    if request.method == "POST":
        password = request.form.get("password")
        email = request.form.get("email")
        existing_user = User.query.filter(User.email == request.form.get('email')).first()
        if not existing_user:
            try:
                new_user = User(
                    email=request.form.get("email"),
                    password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8),
                    name=request.form.get("name")
                )
            except sqlalchemy.exc.OperationalError:
                print("Unable to save user")
                return redirect("/")
            except sqlalchemy.exc.IntegrityError:
                print("This user already exists")
                return redirect("/login")
            else:
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                return redirect("/")
        else:
            flash("Yikes - It looks like you already have an account - login instead")
            return redirect("/login")
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter(User.email == request.form.get("email")).first()
        if user:
            authenticated = check_password_hash(user.password, request.form.get("password"))
            if authenticated:
                login_user(user)
                return redirect("/")
            else:
                flash("Uh oh - that's the wrong password - please try again")
                return redirect("/login")
        else:
            flash("Whoops - doesn't look we have a record of you on file. Please register an account")
            return redirect("/login")
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    user_id = 0
    comments = Comment.query.filter(Comment.blog_id == int(post_id))
    if current_user.is_authenticated:
        user_id = current_user.id
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    logged_in = current_user.is_authenticated
    if request.method == "POST":
        text = request.form.get("comment")
        comment = Comment(
            comment=text,
            blog_id=int(post_id),
            blog=requested_post,
            author_id=current_user.id,
            author=current_user
        )
        db.session.add(comment)
        db.session.commit()
        comments = Comment.query.filter(Comment.blog_id == int(post_id))
        redirect(url_for('show_post', post_id=post_id, user_id=user_id, comments=comments, gravatar=gravatar))
    return render_template("post.html", post=requested_post, comment_form=comment_form, logged_in=logged_in, user_id=user_id, comments=comments, gravatar=gravatar)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@login_check
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
@login_check
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
@login_check
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
