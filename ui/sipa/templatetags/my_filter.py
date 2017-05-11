from django import template
import datetime

register = template.Library()

@register.simple_tag
def current_time(format_string, delta):
    return (datetime.datetime.now()-datetime.timedelta(hours=int(delta))).strftime(format_string)
