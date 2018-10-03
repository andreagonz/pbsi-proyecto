from django import template

register = template.Library()

@register.filter(name='addclass')
def add_class(value, arg):
    return value.as_widget(attrs={'class': arg})

@register.filter(name='fieldtype')
def field_type(field):
    return field.field.widget.__class__.__name__
