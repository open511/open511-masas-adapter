import argparse
import hashlib
import logging
import sys

from lxml import etree
from lxml.builder import ElementMaker
import requests

from open511.converter import open511_convert, ensure_format
from open511.utils.input import load_path, get_jurisdiction_settings
from open511.utils.serialization import NS_ATOM, NS_AGE, NSMAP
from open511.utils import timezone

logger = logging.getLogger(__name__)

def cmdline():
    logging.basicConfig()

    parser = argparse.ArgumentParser(description='Synchronize an Open511 feed to a MASAS hub')
    parser.add_argument('--source', metavar='DOC', type=str,
        required=True,
        help='Open511 document: path, URL, or - to read from stdin')
    parser.add_argument('--masas-secret', metavar='SECRET', type=str,
        required=True, help="Secret token for authentication with MASAS hub")
    parser.add_argument('--masas-author', metavar='URL', type=str,
        required=True, help="URL for the authenticated MASAS user")
    parser.add_argument('--masas-hub', metavar='URL', type=str,
        default='https://sandbox2.masas-sics.ca/hub/feed',
        help='URL to the MASAS Hub feed (default: https://sandbox2.masas-sics.ca/hub/feed)')
    parser.add_argument('--timezone', metavar='TZ', type=str,
        help='Name of the default timezone for these events.'
        ' If not provided, will be downloaded from the linked jurisdiction.')
    arguments = parser.parse_args()

    doc, doc_format = load_path(arguments.source)

    sync_masas(doc, arguments.masas_secret, arguments.masas_author, arguments.masas_hub, timezone=arguments.timezone)


def sync_masas(doc, secret, author_url, feed_url, timezone=None):
    # Get the timezone
    if not timezone:
        jdoc = ensure_format(doc, 'json')
        jurisdiction_urls = set(e['jurisdiction_url'] for e in jdoc['events'])
        if len(jurisdiction_urls) == 0:
            logger.warning("No events provided")
            timezone = 'UTC'
        elif len(jurisdiction_urls) > 1:
            raise Exception("Not all events are from the same jurisdiction")
        else:
            jurisdiction_url = list(jurisdiction_urls)[0]
            timezone = get_jurisdiction_settings(jurisdiction_url)['timezone']

    # Convert the source doc to atom
    doc = open511_convert(doc, "atom", serialize=False, include_expires=True, default_timezone_name=timezone)
    _add_fingerprints(doc)
    entries = _feed_to_dict(doc)

    # Get the existing items on the hub
    auth_header = {'Authorization': "MASAS-Secret %s" % secret}
    push_headers = dict(auth_header)
    push_headers['Content-Type'] = 'application/atom+xml'
    resp = requests.get(feed_url, params={'author': author_url}, headers=auth_header)
    resp.raise_for_status()
    existing_entries = _feed_to_dict(etree.fromstring(resp.content))

    # Figure out what we need to do
    tasks = []
    for entry_id, entry in entries.iteritems():
        task = {'entry': entry, 'entry_id': entry_id}
        if entry_id in existing_entries:
            existing = existing_entries[entry_id]
            if _get_fingerprint(entry) == _get_fingerprint(existing):
                logger.info("%s is up-to-date" % entry_id)
                # Already up-to-date
                continue
            else:
                # Already on MASAS, but we have a different version
                task.update(
                    action='UPDATE',
                    url=_get_url(existing)
                )
        else:
            task['action'] = 'CREATE'
        tasks.append(task)
    for entry_id, entry in existing_entries.iteritems():
        if entry_id not in entries:
            task = {'entry': entry, 'entry_id': entry_id}
            logger.info("%s is on MASAS, but not in provided file" % entry_id)
            task.update({
                'action': 'DELETE',
                'url': _get_url(entry)
            })
            tasks.append(task)

    def _resp_error(resp):
        if str(resp.status_code)[0] == '2':
            return resp
        sys.stderr.write(resp.content)
        logger.error("Error %s on %s" % (resp.status_code, resp.url))

    # Perform queued tasks
    for task in tasks:
        if task['action'] == 'CREATE':
            logger.info("Creating %s" % task['entry_id'])
            _resp_error(requests.post(feed_url, headers=push_headers, data=etree.tostring(task['entry'], pretty_print=True)
                ))
        elif task['action'] == 'UPDATE':
            logger.info("Updating %s" % task['entry_id'])
            _resp_error(requests.put(task['url'], headers=push_headers, data=etree.tostring(task['entry'], pretty_print=True)
                ))
        elif task['action'] == 'DELETE':
            logger.info("Expiring %s" % task['entry_id'])
            entry = task['entry']
            _change_expires(entry)
            _resp_error(requests.put(task['url'], headers=push_headers, data=etree.tostring(entry, pretty_print=True)))

def _change_expires(entry, time=None):
    expires = entry.xpath('age:expires', namespaces=NSMAP)
    if expires:
        expires = expires[0]
    else:
        expires = etree.Element('{%s}expires' % NS_AGE)
        entry.append(expires)
    if not time:
        time = timezone.now()
    expires.text = time

def _get_fingerprint(entry):
    try:
        return entry.xpath('atom:category[@scheme="open511:source_md5"]', namespaces=NSMAP)[0].get('term')
    except IndexError:
        logger.warning("No fingerprint on entry %s" % entry.findtext('id'))
        return None

def _get_url(entry):
    return entry.xpath('atom:link[@rel="edit"]', namespaces=NSMAP)[0].get('href')

def _feed_to_dict(doc):
    d = {}
    for entry in doc.xpath('atom:entry', namespaces=NSMAP):
        id_tag = entry.xpath('atom:category[@scheme="open511:event:id"]', namespaces=NSMAP)
        if not id_tag:
            logger.warning("No Open511 ID tag in entry %s" % entry.findtext('id'))
            continue
        if not entry.xpath('atom:content', namespaces=NSMAP):
            logger.warning("Entry %s has no description, skipping" % id_tag[0].get('term'))
            continue
        d[id_tag[0].get('term')] = entry
    return d

def _add_fingerprints(doc):
    A = ElementMaker(namespace=NS_ATOM, nsmap={None: NS_ATOM})
    
    for entry in doc.xpath('atom:entry', namespaces=NSMAP):
        # Remove IDs, if they're there
        id_tag = entry.xpath('atom:id', namespaces=NSMAP)
        if id_tag:
            entry.remove(id_tag[0])
        entry.append(A('category', label="Open511 Fingerprint", scheme="open511:source_md5",
            term=hashlib.md5(etree.tostring(entry)).hexdigest()))


if __name__ == '__main__':
    cmdline()