from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField
from wtforms.validators import DataRequired

class RuleForm(FlaskForm):
    rule_name = StringField('Rule Name', validators=[DataRequired()])
    protocol = SelectField('Protocol', choices=[('TCP', 'TCP'), ('UDP', 'UDP'), ('ICMP', 'ICMP')], validators=[DataRequired()])
    # For simplicity, conditions will be a simple string like "dport=80,flags=S"
    # A real implementation would have a more dynamic form.
    conditions = StringField('Conditions (e.g., dport=80,flags=S)')
    action = SelectField('Action', choices=[('log', 'Log'), ('block', 'Block')], validators=[DataRequired()])
    submit = SubmitField('Add Rule') 