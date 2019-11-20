import os
import secrets
from datetime import datetime
from flask import Flask, render_template, redirect, flash, url_for, request, abort
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt


# configure app
app = Flask(__name__)


# configure secret key
app.config['SECRET_KEY'] = "010a3a5f052627dc6f665ed2d8ad0daa"


# configure forms
class SignUpForm(FlaskForm):
    firstName = StringField('First name:', validators=[
        DataRequired(), Length(min=2, max=30)])
    lastName = StringField('Last name:', validators=[
        DataRequired(), Length(min=2, max=30)])
    username = StringField('Username:', validators=[
        DataRequired(), Length(min=2, max=20)])
    email = StringField('Email address:', validators=[
        DataRequired(), Email()])
    phone = StringField('Phone number:', validators=[
        DataRequired(), Length(max=20)])
    password = PasswordField('Password:', validators=[
        DataRequired()])
    confirmPassword = PasswordField('Confirm password:', validators=[
        DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(
                'That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(
                'That email address is taken. Please choose a different one.')


class LogInForm(FlaskForm):
    email = StringField('Email address:', validators=[
        DataRequired(), Email()])
    password = PasswordField('Password:', validators=[
        DataRequired()])
    remember = BooleanField('Remember me')
    submit = SubmitField('Log in')


class PostForm(FlaskForm):
    title = StringField('Title:', validators=[DataRequired()])
    department = StringField('Department:', validators=[DataRequired()])
    content = TextAreaField('Details:', validators=[DataRequired()])
    picture = FileField('Update book picture:', validators=[
        FileAllowed(['jpg', 'jpeg', 'png'])])
    submit = SubmitField('Post')


    # configure database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
db = SQLAlchemy(app)


# configure encryption
bcrypt = Bcrypt(app)


# configure login manager
login_manager = LoginManager(app)
login_manager.login_view = "logIn"
login_manager.login_message_category = "info"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# configure models


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(30), nullable=False)
    lastName = db.Column(db.String(30), nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(60), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)

    def __repr__(self):
        return "User(First name: {}, Last name: {}, Username: {}, Email address: {}, Phone number: {})".format(self.firstName, self.lastName, self.username, self.email, self.phone)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(4), nullable=False)
    datePosted = db.Column(db.DateTime, nullable=False, default=datetime.now)
    imageFile = db.Column(db.String(20), nullable=False, default='img.jpg')
    content = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return "Post(Title: {}, Date posted: {}, Details: {})".format(self.title, self.datePosted, self.content)


# route to the homepage (index.html)
@app.route("/")
def index():
    posts = Post.query.all()
    return render_template("index.html", posts=posts)


# route to about
@app.route("/about")
def about():
    return render_template("about.html")


# route to signUp
@app.route("/signUp", methods=["GET", "POST"])
def signUp():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = SignUpForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user = User(firstName=form.firstName.data, lastName=form.lastName.data, username=form.username.data,
                    email=form.email.data, phone=form.phone.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created successfully.', 'success')
        return redirect(url_for('logIn'))
    return render_template("signUp.html", form=form)


# route to logIn
@app.route("/logIn", methods=["GET", "POST"])
def logIn():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LogInForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login failed. Please check email and password.', 'danger')
    return render_template("logIn.html", form=form)


# route to logOut
@app.route("/logOut")
def logOut():
    logout_user()
    return redirect(url_for('index'))


# route to account
@app.route("/account")
@login_required
def account():
    posts = Post.query.filter_by(user_id=current_user.id).all()
    return render_template("account.html", posts=posts)


# save picture
def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static', picture_fn)
    form_picture.save(picture_path)
    return picture_fn


# route to post / new
@app.route("/post/new", methods=["GET", "POST"])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
        post = Post(title=form.title.data,
                    content=form.content.data, author=current_user, imageFile=picture_file, department=form.department.data)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created.', 'success')
        return redirect(url_for('index'))
    return render_template("createPost.html", form=form, title='Create post', legend='New post')


@app.route("/post/<int:post_id>")
def post(post_id):
    post = Post.query.get_or_404(post_id)
    imageFile = url_for('static', filename=post.imageFile)
    return render_template("post.html", post=post, imageFile=imageFile)


@app.route("/post/<int:post_id>/update", methods=["GET", "POST"])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            post.imageFile = picture_file
        post.title = form.title.data
        post.content = form.content.data
        post.department = form.department.data
        db.session.commit()
        flash('Your post has been updated.', 'success')
        return redirect(url_for('post', post_id=post.id))
    elif request.method == "GET":
        form.title.data = post.title
        form.content.data = post.content
    return render_template("createPost.html", form=form, title='Update post', legend='Update post')


@app.route("/post/<int:post_id>/delete", methods=["POST"])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted.', 'success')
    return redirect(url_for('index'))
