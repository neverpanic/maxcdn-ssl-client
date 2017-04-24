"""
Main entry point module for maxcdn-ssl-client
"""

import argparse
import sys

from . import client
from . import conf
from . import exception

def main():
    """
    Main entry point function for maxcdn-ssl-client
    """
    parser = argparse.ArgumentParser(description="Control SSL certificates on MaxCDN using its API")
    parser.add_argument(
        "-c", "--config",
        help="path to configuration file",
        default="maxcdn-ssl-client.yaml")

    subparsers = parser.add_subparsers(help="sub-command help")

    # list action
    parser_list = subparsers.add_parser(
        "list",
        help="list available zones")
    parser_list.set_defaults(func=list_zones)

    parser_update = subparsers.add_parser(
        "update",
        help="update SSL certificate for a zone")
    parser_update.set_defaults(func=update_zone)
    parser_update.add_argument(
        "--zoneid",
        required=True,
        help="Zone ID to update")
    parser_update.add_argument(
        "--certificate",
        required=True,
        help="Path to the certificate file to deploy")
    parser_update.add_argument(
        "--key",
        required=True,
        help="Path to the private key matching the certificate to deploy")
    parser_update.add_argument(
        "--chain",
        help="Path to a file containing the certificate chain to deploy",
        default=None)

    args = parser.parse_args()

    config = conf.Config(args.config)
    apiclient = client.SslApiClient(config.get("company_alias"),
                                    config.get("consumer_key"),
                                    config.get("consumer_secret"))
    try:
        return args.func(apiclient, args)
    except exception.SslApiClientException as ex:
        print(str(ex), file=sys.stderr)
        return 1

def update_zone(apiclient, args):
    """
    Update the SSL certificate of a given zone

    :param apiclient maxcdn_ssl_client.client.SslApiClient: MaxCDN API client
    :param args argparse.Namespace: Command line arguments
    """
    apiclient.add_certificate_for_zone(args.zoneid, args.certificate, args.key, args.chain)
    return 0

def list_zones(apiclient, args): # pylint: disable=unused-argument
    """
    Print a list of all available pull zones

    :param apiclient maxcdn_ssl_client.client.SslApiClient: MaxCDN API client
    :param args argparse.Namespace: Command line arguments
    """
    zones = apiclient.list()
    if not zones:
        print("No pull zones found")
        return 0

    # Define field headers & minimum widths
    field_headers = {
        "cdn_url": "main URL",
        "id": "Zone ID",
        "ssl": "Uses SSL?",
        "ssl_expiry": "SSL certificate expiry",
        "additional_domains": "Additional domains"
    }
    field_widths = {key: len(value) for key, value in field_headers.items()}

    # Helpers to turn API data into human readable strings
    def ssl_type_description(ssl, ssl_sni):
        """
        Convert the SSL enabled flags into a human-readable string, indicating
        whether a domain has SSL on a dedicated IP, SSL on SNI, or no SSL
        support at all.
        """
        if int(ssl):
            return "yes (dedicated IP)"
        if int(ssl_sni):
            return "yes (SNI)"
        return "no"

    def ssl_expiry(sslinfo):
        """
        Convert an SSL expiration date into a human-readable string, printing
        "N/A" is no expiration date is set.
        """
        if sslinfo:
            return sslinfo["date_expiration"]
        return "N/A"

    # Create human-readable sequence of data to display
    data = []
    for zone in zones:
        data.append({
            "cdn_url": zone["cdn_url"],
            "id": zone["id"],
            "ssl": ssl_type_description(zone["ssl"], zone["ssl_sni"]),
            "ssl_expiry": ssl_expiry(zone["sslinfo"]),
            "additional_domains": zone["custom_domains"]
        })

    # Compute field widths
    for zonedata in data:
        for key in field_widths:
            if key in zonedata:
                if isinstance(zonedata[key], list):
                    if zonedata[key]: # ignore empty lists
                        field_widths[key] = max(
                            field_widths[key],
                            max([len(item) for item in zonedata[key]]))
                else:
                    field_widths[key] = max(
                        field_widths[key],
                        len(zonedata[key]))

    widthdict = {key + "_width": value for key, value in field_widths.items()}

    # Print
    fmt = "{cdn_url:{fill}<{cdn_url_width}s}" \
          " | {id:{fill}<{id_width}s}" \
          " | {ssl:{fill}<{ssl_width}s}" \
          " | {ssl_expiry:{fill}<{ssl_expiry_width}s}" \
          " | {additional_domains:{fill}<{additional_domains_width}s}"
    print(fmt.format(**field_headers, **widthdict, fill=" "))
    print(fmt.format(**{key: "" for key, value in field_widths.items()},
                     **widthdict, fill="="))
    for zonedata in data:
        cur = zonedata.copy()
        if zonedata["additional_domains"]:
            del cur["additional_domains"]
            for add_domain in zonedata["additional_domains"]:
                cur["additional_domains"] = add_domain
                print(fmt.format(**cur, **widthdict, fill=" "))
                cur.update({key: "" for key, value in field_widths.items()})
        else:
            cur["additional_domains"] = ""
            print(fmt.format(**cur, **widthdict, fill=" "))
    return 0

if __name__ == "__main__":
    sys.exit(main())
