from django.db import connections

global db
db = None

def dbConn():
    db = connections['data']

    return db