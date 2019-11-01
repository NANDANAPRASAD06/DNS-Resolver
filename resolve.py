"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

# current as of 23 February 2017
ROOT_SERVERS = ("198.41.0.4",
                "192.228.79.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")

domain_cache = {}
dns_cache = {}

timeout = 3

def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}
    cnames = []
    arecords = []
    aaaarecords = []
    mxrecords = []

    target_name = dns.name.from_text(name)

    # lookup CNAME
    response = lookup(target_name, dns.rdatatype.CNAME)

    if response is not None:
        for answers in response.answer:
            for answer in answers:
                cnames.append({"name": answer, "alias": name})

                # Use CNAME answer for the remaining lookups
                target_name = str(answer)[:-1]

    # lookup A
    response = lookup(target_name, dns.rdatatype.A)

    if response is not None:
        for answers in response.answer:
            a_name = answers.name
            for answer in answers:
                if answer.rdtype == 1:  # A record
                    arecords.append({"name": a_name, "address": str(answer)})

    # lookup AAAA
    response = lookup(target_name, dns.rdatatype.AAAA)

    if response is not None:
        for answers in response.answer:
            aaaa_name = answers.name
            for answer in answers:
                if answer.rdtype == 28:  # AAAA record
                    aaaarecords.append(
                        {"name": aaaa_name, "address": str(answer)})

    # lookup MX
    response = lookup(target_name, dns.rdatatype.MX)

    if response is not None:
        for answers in response.answer:
            mx_name = answers.name
            for answer in answers:
                if answer.rdtype == 15:  # MX record
                    mxrecords.append({"name": mx_name,
                                      "preference": answer.preference,
                                      "exchange": str(answer.exchange)})

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords

    return full_response


def _recurlookup(target_name, qtype, servers_list):
    if not servers_list:
        return None
    outbound_query = dns.message.make_query(target_name, qtype)
    for server in servers_list:
        try:
            response = dns.query.udp(outbound_query, server, 3)
        except:
            continue

        if not response:
            continue

        if not response.answer:
            list_of_addresses = []

            if not response.additional:
                ns_records = []

                for list_of_authority_servers in response.authority:
                    for auth in list_of_authority_servers:
                        if auth.rdtype == 6:
                            continue
                        ns_records += [str(auth)[:-1]]

                    for host_name in ns_records:
                        authority_resp = _recurlookup(host_name, 1, ROOT_SERVERS)

                        if authority_resp is not None:
                            for answer in authority_resp.answer:
                                addr_of_ns_recrds = dns_caching(str(answer))

                                response_for_ns = _recurlookup(target_name,qtype, addr_of_ns_recrds)
                                if response_for_ns is not None:
                                    return response_for_ns

            else:
                for additional in response.additional:
                    list_of_addresses += dns_caching(str(additional))
                return _recurlookup(target_name, qtype, list_of_addresses)

        else:
            for answers in response.answer:
                for answer in answers:
                    target_name = str(answer)[:-1]

                    if answer.rdtype == qtype:
                        return response
                    else:
                        if answer.rdtype == 5:
                            return _recurlookup(target_name, qtype, ROOT_SERVERS)


def dns_caching(string):
    type_is = string.split()
    address = []
    for a in type_is:
        if a == 'A':
            v = type_is[0].split(".")
            address = [type_is[-1]]
            if v[-2] not in dns_cache:
                dns_cache[v[-2]] = address
            else:
                if address[0] not in dns_cache[v[-2]]:
                    dns_cache[v[-2]] = dns_cache[v[-2]] + address
    return address


def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata) -> dns.message.Message:
    first_req = str(target_name).split(".")
    tld_domain = first_req[-2]
    if tld_domain in dns_cache:
        cached_address = dns_cache.get(tld_domain)
        return _recurlookup(target_name, qtype, cached_address)
    else:
        return _recurlookup(target_name, qtype, ROOT_SERVERS)


def print_results(results: dict) -> None:
    """
    Take the results of a `lookup` and print them to the screen like the host
    program would.
    """

    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()
    new_list = []
    for i in program_args.name:
        if i not in new_list:
            new_list.append(i)
    for a_domain_name in new_list:
        if a_domain_name in domain_cache:
            print_results(domain_cache[a_domain_name])
        else:
            domain_cache[a_domain_name] = collect_results(a_domain_name)
            print_results(domain_cache[a_domain_name])


if __name__ == "__main__":
    main()