from django.conf.urls import patterns, url, include
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.views.generic import TemplateView
from django.contrib.auth import views as auth_views
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django_statsd.urls import urlpatterns as statsd_patterns

from settings import *

urlpatterns = [
    url(r'^$', 'sipa.views.home', name = 'default' ),

    url(r'^image$', 'sipa.views.image', name = 'image' ),
    url(r'^imageView$', 'sipa.views.imageView', name = 'imageView' ),
    url(r'^imageSave$', 'sipa.views.imageSave', name = 'imageSave' ),

    url(r'^dashboard$', login_required(TemplateView.as_view(template_name='templates/dashboard.html')), name = 'dashboard'),

    url(r'^search$', 'sipa.views.search', name = 'search' ),
    url(r'^searchForm$', login_required(TemplateView.as_view(template_name='templates/searchForm.html')), name = 'searchForm'),

    url(r'^msg$', 'sipa.views.getMsg', name = 'msg' ),

    url(r'^accounts/login/$', auth_views.login, {'template_name': 'templates/login.html', 'authentication_form': AuthenticationForm}, name='login'),
    url(r'^accounts/logout/$', auth_views.logout,  {'next_page': '/'}, name='logout'),

    url(r'^admin/', include(admin.site.urls))
]

urlpatterns += staticfiles_urlpatterns()
urlpatterns += patterns('',
        ('^services/timing/', include(statsd_patterns)),
)

if DEBUG:
    import debug_toolbar
    urlpatterns += patterns('',
        url(r'^__debug__/', include(debug_toolbar.urls)),
    )