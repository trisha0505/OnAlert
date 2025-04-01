from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ReportUpdateForm(FlaskForm):
    status = SelectField('Status', choices=[('Pending', 'Pending'), ('Under Review', 'Under Review'), ('Resolved', 'Resolved')])
    notes = TextAreaField('Admin Notes')
    submit = SubmitField('Update Report')