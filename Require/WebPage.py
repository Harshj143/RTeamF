#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import re
import json
import requests
import pkg_resources
from Wappalyzer import Wappalyzer
from bs4 import BeautifulSoup


class WebPage(object):
    """
    Simple representation of a web page, decoupled
    from any particular HTTP library's API.
    """

    def __init__(self, url, verify=True):
        """
        Initialize a new WebPage object.

        Parameters
        ----------

        url : str
            The web page URL.
        html : str
            The web page content (HTML)
        headers : dict
            The HTTP response headers
        """
        response = requests.get(url, verify=verify, timeout=30)
        self.url = url
        # if use response.text, could have some error
        self.html = response.text
        self.headers = response.headers

        # Parse the HTML with BeautifulSoup to find <script> and <meta> tags.
        self.parsed_html = soup = BeautifulSoup(self.html, "html.parser")
        self.scripts = [script['src'] for script in
                        soup.findAll('script', src=True)]
        self.meta = {
            meta['name'].lower():
                meta['content'] for meta in soup.findAll(
                    'meta', attrs=dict(name=True, content=True))
        }

        self.title = soup.title.string if soup.title else 'None'

        wappalyzer = Wappalyzer.Wappalyzer()
        self.apps = wappalyzer.analyze(self)

    def info(self):
        return {
            "apps": ';'.join(self.apps),
            "title": self.title,
        }
