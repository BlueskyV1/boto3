# Dell EMC stuff
#
#
#
#
#
#
# Dell EMC stuff

from botocore.auth import *

class EmcEcsHmacV1Auth(BaseSigner):

    # List of Query String Arguments of Interest
    QSAOfInterest = ['accelerate', 'acl', 'cors', 'defaultObjectAcl',
                     'location', 'logging', 'partNumber', 'policy',
                     'requestPayment', 'torrent',
                     'versioning', 'versionId', 'versions', 'website',
                     'uploads', 'uploadId', 'response-content-type',
                     'response-content-language', 'response-expires',
                     'response-cache-control', 'response-content-disposition',
                     'response-content-encoding', 'delete', 'lifecycle',
                     'tagging', 'restore', 'storageClass', 'notification',
                     'replication', 'requestPayment', 'isstaleallowed',
                     'endpoint', 'fileaccess']

    def __init__(self, credentials, service_name=None, region_name=None):
        self.credentials = credentials

    def sign_string(self, string_to_sign):
        new_hmac = hmac.new(self.credentials.secret_key.encode('utf-8'),
                            digestmod=sha1)
        new_hmac.update(string_to_sign.encode('utf-8'))
        return encodebytes(new_hmac.digest()).strip().decode('utf-8')

    def canonical_standard_headers(self, headers):
        interesting_headers = ['content-md5', 'content-type', 'date']
        hoi = []
        if 'Date' in headers:
            del headers['Date']
        headers['Date'] = self._get_date()
        for ih in interesting_headers:
            found = False
            for key in headers:
                lk = key.lower()
                if headers[key] is not None and lk == ih:
                    hoi.append(headers[key].strip())
                    found = True
            if not found:
                hoi.append('')
        return '\n'.join(hoi)

    def canonical_custom_headers(self, headers):
        hoi = []
        custom_headers = {}
        for key in headers:
            lk = key.lower()
            if headers[key] is not None:
                if lk.startswith('x-'):
                    custom_headers[lk] = ','.join(v.strip() for v in
                                                  headers.get_all(key))
        sorted_header_keys = sorted(custom_headers.keys())
        for key in sorted_header_keys:
            hoi.append("%s:%s" % (key, custom_headers[key]))
        return '\n'.join(hoi)

    def unquote_v(self, nv):
        """
        TODO: Do we need this?
        """
        if len(nv) == 1:
            return nv
        else:
            return (nv[0], unquote(nv[1]))

    def canonical_resource(self, split, auth_path=None):
        # don't include anything after the first ? in the resource...
        # unless it is one of the QSA of interest, defined above
        # NOTE:
        # The path in the canonical resource should always be the
        # full path including the bucket name, even for virtual-hosting
        # style addressing.  The ``auth_path`` keeps track of the full
        # path for the canonical resource and would be passed in if
        # the client was using virtual-hosting style.
        if auth_path is not None:
            buf = auth_path
        else:
            buf = split.path
        if split.query:
            qsa = split.query.split('&')
            qsa = [a.split('=', 1) for a in qsa]
            qsa = [self.unquote_v(a) for a in qsa
                   if a[0] in self.QSAOfInterest]
            if len(qsa) > 0:
                qsa.sort(key=itemgetter(0))
                qsa = ['='.join(a) for a in qsa]
                buf += '?'
                buf += '&'.join(qsa)
        return buf

    def canonical_string(self, method, split, headers, expires=None,
                         auth_path=None):
        cs = method.upper() + '\n'
        cs += self.canonical_standard_headers(headers) + '\n'
        custom_headers = self.canonical_custom_headers(headers)
        if custom_headers:
            cs += custom_headers + '\n'
        cs += self.canonical_resource(split, auth_path=auth_path)
        return cs

    def get_signature(self, method, split, headers, expires=None,
                      auth_path=None):
        if self.credentials.token:
            del headers['x-amz-security-token']
            headers['x-amz-security-token'] = self.credentials.token
        string_to_sign = self.canonical_string(method,
                                               split,
                                               headers,
                                               auth_path=auth_path)
        logger.debug('StringToSign:\n%s', string_to_sign)
        return self.sign_string(string_to_sign)

    def add_auth(self, request):
        if self.credentials is None:
            raise NoCredentialsError
        logger.debug("Calculating signature using hmacv1 auth.")
        split = urlsplit(request.url)
        logger.debug('HTTP request method: %s', request.method)
        signature = self.get_signature(request.method, split,
                                       request.headers,
                                       auth_path=request.auth_path)
        self._inject_signature(request, signature)

    def _get_date(self):
        return formatdate(usegmt=True)

    def _inject_signature(self, request, signature):
        if 'Authorization' in request.headers:
            # We have to do this because request.headers is not
            # normal dictionary.  It has the (unintuitive) behavior
            # of aggregating repeated setattr calls for the same
            # key value.  For example:
            # headers['foo'] = 'a'; headers['foo'] = 'b'
            # list(headers) will print ['foo', 'foo'].
            del request.headers['Authorization']
        request.headers['Authorization'] = (
            "AWS %s:%s" % (self.credentials.access_key, signature))



# ! I don't think that this is needed as the ecs entry is added in session.py
# Defined at the bottom instead of the top of the module because the Auth
# classes weren't defined yet.
AUTH_TYPE_MAPS = {
    'v2': SigV2Auth,
    'v4': SigV4Auth,
    'v4-query': SigV4QueryAuth,
    'v3': SigV3Auth,
    'v3https': SigV3Auth,
    's3': HmacV1Auth,
    's3-query': HmacV1QueryAuth,
    's3-presign-post': HmacV1PostAuth,
    's3v4': S3SigV4Auth,
    's3v4-query': S3SigV4QueryAuth,
    's3v4-presign-post': S3SigV4PostAuth,
    'emcecs' : EmcEcsHmacV1Auth,
}
