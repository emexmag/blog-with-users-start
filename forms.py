from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, URL
from flask_ckeditor import CKEditorField

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

#Register form
class UserRegisterForm (FlaskForm):
    email = StringField("Email", validators=[DataRequired("You must enter an email address"), Email("You must enter a valid email address")])
    password = PasswordField("Password", validators=[DataRequired("You must enter a password")])
    name = StringField("Your Full Name", validators=[DataRequired("You must enter your full name")])
    submit = SubmitField('Sign me in')

class UserLoginForm(FlaskForm):
        email = StringField("Email", validators=[DataRequired("You must enter an email address"),
                                                 Email("You must enter a valid email address")])
        password = PasswordField("Password", validators=[DataRequired("You must enter a password")])
        submit = SubmitField('Log in')