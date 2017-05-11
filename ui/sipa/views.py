from __future__ import print_function

from django.http import HttpResponse, StreamingHttpResponse
from django.shortcuts import render_to_response
from django.shortcuts import redirect
from django.views.decorators.cache import cache_page
from django.views.decorators.cache import never_cache

from django.core.cache import caches

from django.contrib.auth.decorators import login_required
from django.template import loader, Context

from django.views.decorators.csrf import ensure_csrf_cookie

from django.core.exceptions import ObjectDoesNotExist, ValidationError
from seqdiag import parser, builder, drawer
from django_statsd.clients import statsd

from hashlib import sha1

from sipa.utils import *

import MySQLdb
import re
import binascii
import cgi
import json
import base64
import logging
import traceback

from colour import Color

logger = logging.getLogger('django')

cache = caches['redis']


source_tmpl = """
seqdiag {
    default_fontsize = 16;
    span_width = 100;
    span_height = 40;

    autonumber = True;
    activation = none;

    default_note_color = lightblue;

    %s
}
"""

source_map_tmpl = """
<map name="imgMap" id="msgArea">
    %s
</map>
"""

def escape(t):
    """HTML-escape the text in `t`."""
    return (t
        .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace("'", "&#39;").replace('"', "&quot;")
        )

def getDataFromDb(id=None):
    if id is None:
        raise Exception("ID required")

    timer = statsd.timer("custom.getDataFromDb").start()
    db = dbConn()
    cursor = db.cursor()

    def getCallIDS(cid=None):
        try:
            sql = """
                SELECT
                    DISTINCT(callid)
                FROM
                    sip_capture
                WHERE
                    callid_rc = '%s'
                    AND callid_rc <> ''
                    AND callid <> ''
            """ % MySQLdb.escape_string(cid)

            cache_key = sha1(sql).hexdigest()
            #cache.delete(cache_key)
            c = cache.get(cache_key)

            if c is None:
                cursor.execute(sql)

                print (cursor._last_executed)
                res = []
                for row in cursor:
                    res.append(row)
                    yield row

                cache.add(cache_key, res, 60 * 60 * 24 * 7 )
            else:
                for row in c:
                    yield row

        except Exception as e:
            raise Exception(e)

    try:
        sql = """
            SELECT
                callid
            FROM
                sip_capture
            WHERE
                id = %(id)s
                AND callid <> ''
        """

        cursor.execute(sql, {"id": id})
        print(cursor._last_executed)

        cid = cursor.fetchone()

        if len(cid) < 1:
            raise Exception("callid not found by id %s" % int(id))

        if cid[0] is None:
            raise Exception("callid for %u is None" % int(id))

        where = "(sc.callid = '%(cid)s' OR sc.callid_rc = '%(cid)s') \n" % (
            {"cid": MySQLdb.escape_string(cid[0]) }
        )

        sql = """
            SELECT
                DISTINCT(callid_rc)
            FROM sip_capture
            WHERE
                callid = %(cid)s
                AND callid <> ''
                AND callid_rc IS NOT NULL
                AND callid_rc <> ''
            LIMIT 1
        """

        cursor.execute(sql, {"cid": cid[0]} )
        print(cursor._last_executed)

        callid_rc = cursor.fetchone()

        callids = []
        for row in getCallIDS(callid_rc[0] if callid_rc else cid[0]):
            callids.append(MySQLdb.escape_string(row[0]))

        if len(callids) > 0:
            where += " OR (sc.callid IN (%(cids)s) OR sc.callid_rc IN (%(cids)s)) \n" % (
                {"cids": ', '.join("'%s'" % x for x in callids) }
            )

        if callid_rc is not None and callid_rc[0] is not None:
            where += " OR (sc.callid = '%(cid)s' OR sc.callid_rc = '%(cid)s') \n" % (
                {"cid": MySQLdb.escape_string(callid_rc[0]) }
            )

        sql = """
            SELECT
                INET_NTOA(sc.source_ip) as source_ip,
                INET_NTOA(sc.destination_ip) as destination_ip,
                CONCAT(COALESCE(sc.request_method, ''), COALESCE(sc.response_code, '')) as method,
                sc.id,
                sc.datetime,
                IFNULL(sc.msg, ''),
                SHA1(CONCAT(sc.from, sc.to, sc.source_ip, IFNULL(sc.source_port, '0'), sc.destination_ip, IFNULL(sc.destination_port, '0'), sc.msg)) chsumm
            FROM
                sip_capture sc
            WHERE
                %s
            GROUP BY chsumm
            ORDER BY datetime ASC, id ASC LIMIT 1000
        """ % where

        cache_key = sha1(sql).hexdigest()
        #cache.delete(cache_key)
        c = cache.get(cache_key)

        if c is None:
            cursor.execute(sql)

            print(cursor._last_executed)
            res = []
            for row in cursor:
                res.append(row)
                yield row

            cache.add(cache_key, res)

        else:
            for row in c:
                yield row

    except Exception as e:
        raise Exception(e)
    finally:
        cursor.close()
        timer.stop(send=True)

def getSeqDiagDataAndMap(id=None, includeMsg=0):
    def getColorAndLine(m):
        cl = "black"
        line = "->"

        try:
            code = int(m)
            line = "-->"

            if code in range(100,199):
                cl = "DodgerBlue"

            if code in range(200,299):
                cl = "LimeGreen"
                line = "->"

            if code in range(300,399):
                cl = "yellow"

            if code in range(400,699):
                cl = "red"
                line = "->"

        except Exception as e:
            pass

        return (cl, line)

    ret = {'flow': '', 'areaImgMap': '', 'msg': {}, 'status': 'OK'}
    timer = statsd.timer("custom.getSeqDiagDataAndMap").start()

    try:
        if id is None:
            raise Exception("ID required")

        ips = []

        x1 = 170
        y1 = 110
        y2 = 150

        iy = 80
        ix = x1/2

        i = 0

        for row in getDataFromDb(id):
            note = escape( row[5].splitlines()[0] )
            note = note.replace('SIP/2.0', '').replace('\n', ' ').replace('\r', '')

            if row[0] not in ips:
                ips.append(row[0])

            if row[1] not in ips:
                ips.append(row[1])

            cl, line = getColorAndLine(row[2])
            ret['flow'] += "%s %s %s  [label = '%s', note = '%s', color = '%s' ]; \n" % (
                    row[0], line, row[1],
                    row[2],
                    note.strip(),
                    cl
                )

            #print "%s -> %s: %s \n" % (row[0], row[1], note)

            px = min(ips.index(row[0]), ips.index(row[1]))+1
            pxm = max(abs(ips.index(row[0])-ips.index(row[1])), 1)
            if px > 1:
                #px = max(abs(ips.index(row[0]) - ips.index(row[1])), px)
                xx1 = x1*px+(28*px)
                if px > 2:
                    xx1 += (25-px)*(px-1)

                xx2 = xx1+x1*pxm+(56*pxm)
            else:
                xx1 = x1*px
                xx2 = xx1+(x1+50)*pxm

            #logger.debug("%s - %s" % (row[0], row[1]))

            ret['areaImgMap'] += '<area id="msgArea" shape="rect" coords="%u,%u,%u,%u" href="javascript:openDiag(%u)" >\n' % (
                    xx1,
                    y1+iy*i,

                    xx2,
                    y2+iy*i,

                    int(row[3])
            )
            i+=1

            if includeMsg is not None and includeMsg == "1":
                ret['msg'][row[3]] = ""
                for m in getMsgById(row[3]):
                    d = {}
                    d[row[3]] = m[0]
                    ret['msg'][row[3]] = cgi.escape(m[0]).encode('ascii', 'xmlcharrefreplace')

        if i >= 1000:
            ret['flow'] += "=== Limit reached ==="

        ret['flow'] = source_tmpl  % ret['flow']

        print(ret['flow'])

        ret['areaImgMap'] = source_map_tmpl % ret['areaImgMap']

    except Exception as e:
        ret['flow'] = repr(e)
        ret['status'] = "error"
        ret['traceback'] = traceback.format_exc()
        pass

    finally:
        timer.stop(send=True)

    return ret

@login_required
def home(request):
    return redirect('searchForm')

@login_required
@ensure_csrf_cookie
@never_cache
#@cache_page(60 * 2, cache="redis")
def search(request):
    def genrgb(str, malformed):
        intcol = binascii.crc32(str.strip())

        if not malformed:
            r = "%s" % colors[intcol % len(colors)]
        else:
            r = "%s" % colors_red[intcol % len(colors_red)]
        return r

    ret = {}
    ret["result"] = "unknown"
    ret["msg"] = "unknown msg"
    ret["rows"] = []

    response = StreamingHttpResponse(content_type='application/json')

    try:
        where = []

        QueryDict = request.GET

        limit = QueryDict.get('rows')
        if limit is None or limit == "":
            limit = 10

        colors = list(Color("LightGreen").range_to(Color("MediumAquaMarine", luminance=0.9), 1000 ))
        colors_red = list(Color("Salmon", luminance=0.5).range_to(Color("Tomato", luminance=0.9), 1000 ))

        page = QueryDict.get('page')
        if page is None or page == "":
            page = 1

        offset = int(max(int(page)-1, 0))*int(limit)

        grouping = QueryDict.get('grouping')
        if grouping is None:
            grouping = "1"

        malformed = QueryDict.get('malformed')
        if malformed == "1":
            where.append("malformed = 1")

        src_ip = QueryDict.get('src_ip')
        if src_ip is not None and src_ip != "":
            where.append("source_ip = INET_ATON('%s') " % MySQLdb.escape_string(src_ip))

        dst_ip = QueryDict.get('dst_ip')
        if dst_ip is not None and dst_ip != "":
            where.append("destination_ip = INET_ATON('%s') " % MySQLdb.escape_string(dst_ip))

        sip_callid = QueryDict.get('sip_callid')
        if sip_callid is not None and sip_callid != "":
            where.append("(callid = '%(callid)s' OR callid_rc = '%(callid)s') " %
                         {"callid": MySQLdb.escape_string(sip_callid )}
            )

        sip_method = QueryDict.get('sip_method')
        if sip_method is not None and sip_method != "":
            where.append("request_method = '%s' " % MySQLdb.escape_string(sip_method))

        from_user = QueryDict.get('from_user')
        if from_user is not None and from_user != "":
            where.append("("
                         "`from` = '%(from)s' "
                         "OR `from` = '+%(from)s' "
                         "OR `from` = '+1%(from)s' "
                         "OR `from` = '1%(from)s'"
                         "OR `from` like '%(from)s'"
                         "OR `from` like '+%(from)s'"
                         "OR `from` like '+1%(from)s'"
                         "OR `from` like '1%(from)s'"
                         ")"
                         % {"from": MySQLdb.escape_string(from_user) })

        to_user = QueryDict.get('to_user')
        if to_user is not None and to_user != "":
            where.append("("
                         "`to` = '%(to)s' "
                         "OR `to` = '+1%(to)s' "
                         "OR `to` = '+%(to)s' "
                         "OR `to` = '1%(to)s'"
                         "OR `to` like '%(to)s'"
                         "OR `to` like '+%(to)s'"
                         "OR `to` like '+1%(to)s'"
                         "OR `to` like '1%(to)s'"
                         ")"
                         % {"to": MySQLdb.escape_string(to_user) })

        date_start = QueryDict.get('date_start')
        if date_start is not None and date_start != "":
            where.append("sc.datetime >= '%s' " % MySQLdb.escape_string(date_start))

        date_end = QueryDict.get('date_end')
        if date_end is not None and date_end != "":
            where.append("sc.datetime <= '%s' " % MySQLdb.escape_string(date_end))

        if not where:
            where.append("1=1")

        sql = """
            SELECT SQL_CALC_FOUND_ROWS
                sc.id,
                CAST(UNIX_TIMESTAMP(sc.datetime) AS SIGNED) as datetime,
                CONCAT(INET_NTOA(sc.source_ip), ':', IFNULL(sc.source_port, '0')) as source_ip,
                CONCAT(INET_NTOA(sc.destination_ip), ':', IFNULL(sc.destination_port, '0') ) as destination_ip,
                sc.callid,
                CONCAT(COALESCE(sc.request_method, ''), COALESCE(sc.response_code, '')) as method,
                sc.from,
                sc.to,
                sc.malformed
            FROM
                sip_capture sc
            WHERE
                %s
            %s
            ORDER BY sc.datetime ASC, sc.id ASC LIMIT %u OFFSET %u
        """ % (
                " \n AND ".join(where),
                "" if grouping == "0" else "GROUP BY sc.callid",
                int(limit),
                int(offset)
            )

        db = dbConn()
        cursor = db.cursor()

        try:
            cache_key = sha1(sql).hexdigest()
            #cache.delete(cache_key)
            c = cache.get(cache_key)

            if c is None:
                cursor.execute(sql)
                print(cursor._last_executed)

                if cursor.rowcount == 0:
                    raise ObjectDoesNotExist("Records not found")

                res = {}

                results = cursor.fetchall()
                res['results'] = results

                cursor.execute("SELECT FOUND_ROWS()")
                found_rows = cursor.fetchone()

                res['found_rows'] = found_rows
                cache.add(cache_key, res, 30 )
            else:
                found_rows = c['found_rows']
                results = c['results']

            #print sql
            #cursor.execute(sql)
            #print cursor._last_executed

            for row in results:
                ret["rows"].append({'id': row[0],
                                    'date': row[1],
                                    'source_ip': row[2],
                                    'destination_ip': row[3],
                                    'callid': row[4],
                                    'method': row[5],
                                    'from_user': row[6],
                                    'to_user': row[7],
                                    'color': genrgb("%s %s" % (row[2], row[3]), row[8])
                                })

            ret["result"] = "success"
            ret["msg"] = "success msg"
            ret["total"] = found_rows[0]

        except ObjectDoesNotExist as e:
            ret["result"] = "warning"
            ret["msg"] = str(e)

            response.status_code = 404
            pass

        except Exception as e:
            ret["result"] = "error"
            ret["msg"] = repr(e)
            ret['traceback'] = traceback.format_exc()

            response.status_code = 500
            pass

        finally:
            cursor.close()


    except Exception as e:
        ret["result"] = "error"
        ret['traceback'] = traceback.format_exc()
        ret["msg"] = repr(e)
        response.status_code = 500

    json_data = json.dumps(ret)

    response.streaming_content = json_data

    return response

@login_required
@never_cache
def imageView(request):
    QueryDict = request.GET
    id = QueryDict.get('id')

    return render_to_response('templates/imageView.html',{'id': id})

@login_required
@never_cache
def imageSave(request):
    img = image(request)
    msg = {}

    QueryDict = request.GET
    id = QueryDict.get('id')
    if id is None:
        raise Exception("ID required")

    data = json.loads(img.content)

    for k,v in data['msg'].iteritems():
        msg[k] = v

    t = loader.get_template('templates/imageDownload.html')
    c = Context({
        'title': "ID: %s by %s" % (id, request.user.get_username()),
        'image': data['image'],
        'imageMap': data['imageMap'],
        'msg': json.dumps(msg)
    })

    response = HttpResponse()
    response['Content-Disposition'] = 'attachment; filename="sipc-%s.html"' % id
    response.write(t.render(c))
    response.set_cookie('fileDownload', 'true', path="/")

    return response

@login_required
@cache_page(60 * 60 * 24 * 3, cache="redis")
def image(request):

    ret = {}
    response = HttpResponse(content_type='application/json')

    try:
        QueryDict = request.GET
        id = QueryDict.get('id')
        download = QueryDict.get('download')

        if id is None:
            raise Exception("ID required")

        data = getSeqDiagDataAndMap(id, download)

        buffer = ''

        if data['status'] == "OK":
            tree = parser.parse_string(data['flow'])
            diagram = builder.ScreenNodeBuilder.build(tree)

            draw = drawer.DiagramDraw('png', diagram, buffer, antialias=False,
                                      font='/usr/share/fonts/wine-tahoma-fonts/tahoma.ttf')
            draw.draw()
            img = draw.save()

            ret['image'] = 'data:image/png;base64,%s' % base64.b64encode(img)
            ret['imageMap'] = data['areaImgMap']
            ret['msg'] = data['msg']
        else:
            response.status_code = 500
            ret['image'] = data['flow']

    except Exception as e:
        ret['image'] = str(e)
        response.status_code = 500
        pass

    json_data = json.dumps(ret)

    response.content = json_data

    return response

def getMsgById(id=None):
    if id is None:
        raise Exception("ID required")

    db = dbConn()
    cursor = db.cursor()

    try:
        sql = """
            SELECT
                CONCAT(
                    'DateTime: ', sc.datetime,
                    '\n',
                    'SRC/DST IP: ', INET_NTOA(sc.source_ip), ':', IFNULL(sc.source_port, '0'),
                    ' -> ',
                    INET_NTOA(sc.destination_ip), ':', IFNULL(sc.destination_port, '0'),
                    '\n\n',
                    sc.msg
                ) AS msg
            FROM
                sip_capture sc
            WHERE
                sc.id = %u
            LIMIT 1
        """ % int(id)

        cache_key = sha1(sql).hexdigest()
        #cache.delete(cache_key)

        c = cache.get(cache_key)

        if c is None:
            cursor.execute(sql)
            print (cursor._last_executed)

            for row in cursor:
                cache.add(cache_key, row, 60 * 60 * 24 * 7 )
                yield row
        else:
            yield c

    except Exception as e:
        raise Exception(e)
    finally:
        cursor.close()

@login_required
#@never_cache
@cache_page(60 * 60 * 24 * 3, cache="redis")
def getMsg(request):
    if request.method == 'POST':
        return

    QueryDict = request.GET
    id = QueryDict.get('id')

    response = HttpResponse(content_type='application/json')

    msg = None
    try:
        if id is None:
            raise Exception("ID required")

        for row in getMsgById(id):
            msg = row[0]

    except Exception as e:
        msg = repr(e)
        response.status_code = 500
        pass

    response.content = json.dumps({'msg': cgi.escape(msg).encode('ascii', 'xmlcharrefreplace') })

    return response