from settings import *
from fnmatch import fnmatch
import os

class glob_list(list):
    def __contains__(self, key):
        for elt in self:
            if fnmatch(key, elt):
                return True
        return False

AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'dpam.backends.PAMBackend',
)

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    },
    'data': {
        'HOST': os.environ.get('SIPA_DATA_HOST'),
        'NAME': os.environ.get('SIPA_DATA_NAME'),
        'ENGINE': 'django.db.backends.mysql',
        'USER': os.environ.get('SIPA_DATA_USER'),
        'PASSWORD': os.environ.get('SIPA_DATA_PASSWORD'),
        'OPTIONS': {
            'compress': True
        }
    }
}

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
    },
    'shm': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': '/dev/shm/',
    },
    'redis': {
        'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
    },
    'redis2': {
        'BACKEND': 'redis_cache.RedisCache',
        'LOCATION': '127.0.0.1:6379',
        'OPTIONS': {
            'COMPRESSOR_CLASS': 'redis_cache.compressors.ZLibCompressor',
            'COMPRESSOR_CLASS_KWARGS': {
                'level': 5,
            },
            'CONNECTION_POOL_CLASS': 'redis.BlockingConnectionPool',
            'CONNECTION_POOL_CLASS_KWARGS': {
                'max_connections': 10
            },
        }
    }
}

CSRF_COOKIE_SECURE = False

STATIC_ROOT = os.path.join(PROJECT_ROOT, 'static')
STATIC_URL = '/static/'

STATICFILES_DIRS = (
    os.path.join(PROJECT_ROOT, 'assets'),
)

STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
)

INSTALLED_APPS += (
    'debug_toolbar',
    'django_statsd',
    'gunicorn',
    'sipa',
    'dpam',
)

MIDDLEWARE_CLASSES += (
    'django.middleware.cache.UpdateCacheMiddleware',
    'django.middleware.cache.FetchFromCacheMiddleware',
    'debug_toolbar.middleware.DebugToolbarMiddleware',
)

MIDDLEWARE_CLASSES = (
    'django_statsd.middleware.GraphiteRequestTimingMiddleware',
    'django_statsd.middleware.GraphiteMiddleware',
) + MIDDLEWARE_CLASSES

DEBUG_TOOLBAR_PATCH_SETTINGS = False
DEBUG_TOOLBAR_PANELS = [
    'debug_toolbar.panels.versions.VersionsPanel',
    'debug_toolbar.panels.timer.TimerPanel',
    'debug_toolbar.panels.settings.SettingsPanel',
    'debug_toolbar.panels.headers.HeadersPanel',
    'debug_toolbar.panels.request.RequestPanel',
    'debug_toolbar.panels.sql.SQLPanel',
    'debug_toolbar.panels.staticfiles.StaticFilesPanel',
    'debug_toolbar.panels.templates.TemplatesPanel',
    'debug_toolbar.panels.cache.CachePanel',
    'debug_toolbar.panels.signals.SignalsPanel',
    'debug_toolbar.panels.logging.LoggingPanel',
    'debug_toolbar.panels.redirects.RedirectsPanel',
]

STATSD_CLIENT = 'django_statsd.clients.normal'

DEBUG_TOOLBAR_CONFIG = {
    'INTERCEPT_REDIRECTS': False,
    'RENDER_PANELS': True,
}

STATSD_HOST = os.environ.get('STATSD_HOST')
STATSD_PORT = int(os.environ.get('STATSD_PORT'))
STATSD_PREFIX = "ui"

SHOW_TOOLBAR_CALLBACK = lambda x: True

TEMPLATES[0]['OPTIONS']['debug'] = True

ALLOWED_HOSTS = glob_list(['127.0.0.1', '*.*.*.*'])

FONT = '/usr/share/wine/fonts/tahoma.ttf'

LOGGING = {
    'version': 1,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose'
            },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    }
}

PAM_SERVICE = "moriot"

if DEBUG:
    INTERNAL_IPS = glob_list(['127.0.0.1'])
