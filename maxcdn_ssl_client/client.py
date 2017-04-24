"""
Abstraction for MaxCDN's SSL abstraction
"""

from maxcdn import MaxCDN

from . import exception
from . import cryptography

class SslApiClient(object):
    """
    High-level abstraction of MaxCDN's SSL API
    """

    __slots__ = ('_api', )

    def __init__(self, alias, key, secret, **kwargs):
        """
        Establish a connection to MaxCDN using the given alias, key and secret.
        Additional parameters accepted by the MaxCDN API client can be given in
        **kwargs and will be passed through unmodified.

        :param str alias: The alias for the MaxCDN API
        :param str key: The key for the MaxCDN API
        :param str secret: The secret for the MaxCDN API
        """
        self._api = MaxCDN(alias, key, secret, **kwargs)

    def _request(self, action, url, **kwargs):
        """
        Send a request to the server using the given action to the given URL
        and handle exceptions and invalid repsonses.

        :param callable action: The action to call for the given URL
        :param str url: The resource to request form the API
        :rtype dict: The server's JSON response
        """
        try:
            response = action(url, **kwargs)
        except Exception as ex:
            raise exception.CommunicationException(
                "Error while communicating with the API server", ex)
        return self._expect_success(response)

    def _get(self, url, **kwargs):
        """
        Send a GET request to the server and handle exceptions and invalid
        responses.

        :param str url: The resource to request from the API
        :rtype dict: The server's JSON response
        """
        return self._request(self._api.get, url, **kwargs)

    def _post(self, url, **kwargs):
        """
        Send a POST request to the server and handle exceptions and invalid
        responses.

        :param str url: The resource to request from the API
        :rtype dict: The server's JSON response
        """
        return self._request(self._api.post, url, **kwargs)

    def _put(self, url, **kwargs):
        """
        Send a PUT request to the server and handle exceptions and invalid
        responses.

        :param str url: The resource to request from the API
        :rtype dict: The server's JSON response
        """
        return self._request(self._api.put, url, **kwargs)

    @staticmethod
    def _expect_success(json):
        """
        Verify success given a JSON response. Expects a 200 series return code
        and will raise an exception if a different return code occurred.

        :param dict json: The decoded JSON object returned by the server
        :rtype dict: The object passed in on success, raises on error
        """
        try:
            code = json['code']
            if code < 200 or code >= 300:
                raise exception.ApiFailureException(
                    "Expected success, but return code was {:d}".format(code))
        except (ValueError, KeyError) as ex:
            raise exception.ApiFailureException(
                "Expected valid JSON object with 'code' property", ex)
        return json

    def list(self):
        """
        Obtain a list of all configured pull zones in this account, whether
        they have SSL enabled, the expiration date of their current SSL
        certificate, if any and a list of all assigned custom domains.
        """
        raw_zones = self._get("/zones/pull.json")

        zones = []
        for zone in raw_zones["data"]["pullzones"]:
            zones.append(zone)

        for zone in zones:
            _, aux_domains = self.domains_for_zone(zone["id"])
            zone["custom_domains"] = aux_domains

        for zone in zones:
            zone["sslinfo"] = {}
            if int(zone["ssl"]) or int(zone["ssl_sni"]):
                zone["sslinfo"] = self.sslinfo_for_zone(zone["id"])

        return zones

    def domains_for_zone(self, zone_id):
        """
        Return a tuple of the main domain and a list of additional domains for
        a given pull zone ID. Use this to make sure all domains associated with
        a pull zone are present in a certificate.

        :param str zone_id: MaxCDN pull zone ID to query for domains
        :rtype tuple: Tuple (str, list) where the string is the main domain and
                      the list contains a number of strings with subject alt
                      names.
        """
        raw_zoneinfo = self._get("/zones/pull.json/{}".format(zone_id))
        main_domain = raw_zoneinfo["data"]["pullzone"]["cdn_url"]

        raw_customdomains = self._get("/zones/pull/{}/customdomains.json".format(zone_id))
        aux_domains = []
        for raw_domain in raw_customdomains["data"]["customdomains"]:
            aux_domains.append(raw_domain["custom_domain"])

        return (main_domain, sorted(aux_domains))

    def zone(self, zone_id):
        """
        Return the zone information for a given pull zone ID. Use this to
        obtain detailed information about a specific zone.

        :param str zone_id: MaxCDN pull zone ID to query for SSL information
        :rtype dict: Dictionary of zone properties
        """
        raw_zoneinfo = self._get("/zones/pull.json/{}".format(zone_id))
        return raw_zoneinfo["data"]["pullzone"]

    def sslinfo_for_zone(self, zone_id):
        """
        Return the SSL information for a given pull zone ID. Use this to obtain
        the SSL ID to replace and the expiration date of the current
        certificate.

        :param str zone_id: MaxCDN pull zone ID to query for SSL information
        :rtype dict: The MaxCDN SSL information object
        """
        raw_sslinfo = self._get("/zones/pull/{}/ssl.json".format(zone_id))
        return raw_sslinfo["data"]["ssl"]

    @staticmethod
    def _load_files(crt_file, key_file, bundle_file=None):
        """
        Load data from the given files and return the contents of the file as
        a tuple of bytestrings.

        :param str crt_file: File name of the certificate file
        :param str key_file: File name of the private key file
        :param str bundle_file: Optional file name of the CA bundle file
        :rtype tuple: A tuple of (crt, key, bundle) read from the given files
        """
        try:
            with open(crt_file, "rb") as crtf:
                crt = crtf.read()
        except OSError as ex:
            raise exception.LogicException(
                "Failed to load certificate file {}: {}".format(crt_file, str(ex)))

        try:
            with open(key_file, "rb") as keyf:
                key = keyf.read()
        except OSError as ex:
            raise exception.LogicException(
                "Failed to load key file {}: {}".format(key_file, str(ex)))

        try:
            bundle = b""
            if bundle_file:
                with open(bundle_file, "rb") as bundlef:
                    bundle = bundlef.read()
        except OSError as ex:
            raise exception.LogicException(
                "Failed to load CA bundle file {}: {}".format(bundle_file, str(ex)))

        return (crt, key, bundle)

    def add_certificate_for_zone(self, zone_id, crt_file, key_file, bundle_file=None):
        # pylint: disable=too-many-locals
        """
        Create a new SSL certificate from the given certificate, key and bundle
        file and change the pull zone identified by the given zone ID to use
        this certificate. Verifies that the given certificate matches the given
        private key and that all domains associated with the given pull zone
        are present in the certificate, either as Common Name, or as Subject
        Alternative Name.

        :param str zone_id: The MaxCDN pull zone ID
        :param str crt_file: The filename of the certificate file
        :param str key_file: The filename of the private key file
        :param str bundle_file: The filename of a chain of intermediate
                                certificates, if required.
        """

        ## Load certificate into memory
        crt, key, bundle = self._load_files(crt_file, key_file, bundle_file)

        ## Decode and verify sanity and match of key and certificate
        try:
            x509_crt = cryptography.load_x509(crt)
        except ValueError as ex:
            raise exception.CryptographyException(
                "Failed to load certificate file: {}".format(str(ex)))
        try:
            private_key = cryptography.load_privkey(key)
        except ValueError as ex:
            raise exception.CryptographyException(
                "Failed to load private key file: {}".format(str(ex)))

        if not cryptography.key_matches_x509_crt(private_key, x509_crt):
            raise exception.CryptographyException(
                "Given key does not match given certificate")

        ## Ensure certificate is valid and not expired
        if not cryptography.x509_is_currently_valid(x509_crt):
            raise exception.CryptographyException(
                "Given certificate is not yet or no longer valid")

        ## Verify certificate has all domains used in the zone
        domains_in_crt = set()
        common_name = cryptography.get_x509_cn(x509_crt)
        if common_name:
            domains_in_crt.add(common_name)
        domains_in_crt = domains_in_crt.union(cryptography.get_x509_sans(x509_crt))

        main_domain, aux_domains = self.domains_for_zone(zone_id)
        domains_in_zone = set()
        domains_in_zone.add(main_domain)
        domains_in_zone = domains_in_zone.union(aux_domains)

        missing_domains = domains_in_zone - domains_in_crt
        if missing_domains:
            raise exception.LogicException(
                "Given certificate is missing domains: {!r}".format(
                    sorted(missing_domains)))

        ## Post certificate, key and bundle to SSL API to get an SSL ID
        ssl_id = self._post("/ssl.json", data={
            "ssl_crt": crt,
            "ssl_key": key,
            "ssl_cabundle": bundle
        })["data"]["ssl"]["id"]

        ## Update zone to use new certificate
        self._put("/zones/pull/{}/ssl.json".format(zone_id), data={
            "ssl_id": ssl_id,
            # Only set use_sni to 0 if we have SSL on a dedicated IP
            "ssl_sni": 0 if int(self.zone(zone_id)["ssl"]) else 1
        })
