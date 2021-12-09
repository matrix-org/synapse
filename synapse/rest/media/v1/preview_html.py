# Copyright 2021 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import itertools
import logging
import re
from typing import TYPE_CHECKING, Dict, Generator, Iterable, Iterator, Optional, Union

if TYPE_CHECKING:
    from bs4 import BeautifulSoup
    from bs4.element import PageElement, Tag

logger = logging.getLogger(__name__)

_content_type_match = re.compile(r'.*; *charset="?(.*?)"?(;|$)', flags=re.I)


def decode_body(body: Union[bytes, str], uri: str) -> Optional["BeautifulSoup"]:
    """
    This uses BeautifulSoup to parse the HTML document.

    Args:
        body: The HTML document, as bytes.
        uri: The URI used to download the body.
        content_type: The Content-Type header.

    Returns:
        The parsed HTML body, or None if an error occurred during processed.
    """
    # If there's no body, nothing useful is going to be found.
    if not body:
        return None

    from bs4 import BeautifulSoup
    from bs4.builder import ParserRejectedMarkup

    try:
        soup = BeautifulSoup(body, "lxml")
        # If an empty document is returned, convert to None.
        if not len(soup):
            return None
        return soup
    except ParserRejectedMarkup:
        logger.warning("Unable to decode HTML body for %s", uri)
        return None


def parse_html_to_open_graph(soup: "BeautifulSoup") -> Dict[str, Optional[str]]:
    """
    Calculate metadata for an HTML document.

    This uses BeautifulSoup to search the HTML document for Open Graph data.

    Args:
        soup: The parsed HTML document.

    Returns:
        The Open Graph response as a dictionary.
    """

    # if we see any image URLs in the OG response, then spider them
    # (although the client could choose to do this by asking for previews of those
    # URLs to avoid DoSing the server)

    # "og:type"         : "video",
    # "og:url"          : "https://www.youtube.com/watch?v=LXDBoHyjmtw",
    # "og:site_name"    : "YouTube",
    # "og:video:type"   : "application/x-shockwave-flash",
    # "og:description"  : "Fun stuff happening here",
    # "og:title"        : "RemoteJam - Matrix team hack for Disrupt Europe Hackathon",
    # "og:image"        : "https://i.ytimg.com/vi/LXDBoHyjmtw/maxresdefault.jpg",
    # "og:video:url"    : "http://www.youtube.com/v/LXDBoHyjmtw?version=3&autohide=1",
    # "og:video:width"  : "1280"
    # "og:video:height" : "720",
    # "og:video:secure_url": "https://www.youtube.com/v/LXDBoHyjmtw?version=3",

    og: Dict[str, Optional[str]] = {}
    for tag in soup.find_all("meta", property=re.compile(r"^og:"), content=True):
        # if we've got more than 50 tags, someone is taking the piss
        if len(og) >= 50:
            logger.warning("Skipping OG for page with too many 'og:' tags")
            return {}
        og[tag["property"]] = tag["content"]

    # TODO: grab article: meta tags too, e.g.:

    # "article:publisher" : "https://www.facebook.com/thethudonline" />
    # "article:author" content="https://www.facebook.com/thethudonline" />
    # "article:tag" content="baby" />
    # "article:section" content="Breaking News" />
    # "article:published_time" content="2016-03-31T19:58:24+00:00" />
    # "article:modified_time" content="2016-04-01T18:31:53+00:00" />

    if "og:title" not in og:
        # do some basic spidering of the HTML
        title = soup.find(("title", "h1", "h2", "h3"))
        if title and title.string:
            og["og:title"] = title.string.strip()
        else:
            og["og:title"] = None

    if "og:image" not in og:
        # TODO: extract a favicon failing all else
        meta_image = soup.find("meta", image="image")
        if meta_image:
            og["og:image"] = meta_image["content"]
        else:
            # TODO: consider inlined CSS styles as well as width & height attribs
            def greater_than(tag: "Tag") -> bool:
                if "width" not in tag or "height" not in tag:
                    return False
                try:
                    return int(tag["width"]) > 10 and int(tag["height"]) > 10
                except ValueError:
                    return False

            images = soup.find_all("img", src=True, width=greater_than)
            images = sorted(
                images,
                key=lambda i: (-1 * float(i["width"]) * float(i["height"])),
            )
            if not images:
                images = soup.find_all("img", src=True)
            if images:
                og["og:image"] = images[0]["src"]

    if "og:description" not in og:
        meta_description = soup.find("meta", description="description")
        if meta_description:
            og["og:description"] = meta_description["content"]
        else:
            og["og:description"] = parse_html_description(soup)
    elif og["og:description"]:
        # This must be a non-empty string at this point.
        assert isinstance(og["og:description"], str)
        og["og:description"] = summarize_paragraphs([og["og:description"]])

    # TODO: delete the url downloads to stop diskfilling,
    # as we only ever cared about its OG
    return og


def parse_html_description(soup: "BeautifulSoup") -> Optional[str]:
    """
    Calculate a text description based on an HTML document.

    Grabs any text nodes which are inside the <body/> tag, unless they are within
    an HTML5 semantic markup tag (<header/>, <nav/>, <aside/>, <footer/>), or
    if they are within a <script/> or <style/> tag.

    This is a very very very coarse approximation to a plain text render of the page.

    Args:
        soup: The parsed HTML document.

    Returns:
        The plain text description, or None if one cannot be generated.
    """

    TAGS_TO_REMOVE = (
        "header",
        "nav",
        "aside",
        "footer",
        "script",
        "noscript",
        "style",
    )

    # Split all the text nodes into paragraphs (by splitting on new
    # lines)
    text_nodes = (
        re.sub(r"\s+", "\n", el).strip()
        for el in _iterate_over_text(soup.find("body"), *TAGS_TO_REMOVE)
    )
    return summarize_paragraphs(text_nodes)


def _iterate_over_text(
    soup: Optional["Tag"], *tags_to_ignore: Iterable[str]
) -> Generator[str, None, None]:
    """Iterate over the document returning text nodes in a depth first fashion,
    skipping text nodes inside certain tags.
    """
    if not soup:
        return

    from bs4.element import NavigableString, Tag

    # This is basically a stack that we extend using itertools.chain.
    # This will either consist of an element to iterate over *or* a string
    # to be returned.
    elements: Iterator["PageElement"] = iter([soup])
    while True:
        el = next(elements, None)
        if el is None:
            return

        # Do not consider sub-classes of NavigableString since those represent
        # comments, etc.
        if type(el) == NavigableString:
            yield str(el)
        elif isinstance(el, Tag) and el.name not in tags_to_ignore:
            # We add to the stack all the elements children.
            elements = itertools.chain(el.contents, elements)


def summarize_paragraphs(
    text_nodes: Iterable[str], min_size: int = 200, max_size: int = 500
) -> Optional[str]:
    """
    Try to get a summary respecting first paragraph and then word boundaries.

    Args:
        text_nodes: The paragraphs to summarize.
        min_size: The minimum number of words to include.
        max_size: The maximum number of words to include.

    Returns:
        A summary of the text nodes, or None if that was not possible.
    """

    # TODO: Respect sentences?

    description = ""

    # Keep adding paragraphs until we get to the MIN_SIZE.
    for text_node in text_nodes:
        if len(description) < min_size:
            text_node = re.sub(r"[\t \r\n]+", " ", text_node)
            description += text_node + "\n\n"
        else:
            break

    description = description.strip()
    description = re.sub(r"[\t ]+", " ", description)
    description = re.sub(r"[\t \r\n]*[\r\n]+", "\n\n", description)

    # If the concatenation of paragraphs to get above MIN_SIZE
    # took us over MAX_SIZE, then we need to truncate mid paragraph
    if len(description) > max_size:
        new_desc = ""

        # This splits the paragraph into words, but keeping the
        # (preceding) whitespace intact so we can easily concat
        # words back together.
        for match in re.finditer(r"\s*\S+", description):
            word = match.group()

            # Keep adding words while the total length is less than
            # MAX_SIZE.
            if len(word) + len(new_desc) < max_size:
                new_desc += word
            else:
                # At this point the next word *will* take us over
                # MAX_SIZE, but we also want to ensure that its not
                # a huge word. If it is add it anyway and we'll
                # truncate later.
                if len(new_desc) < min_size:
                    new_desc += word
                break

        # Double check that we're not over the limit
        if len(new_desc) > max_size:
            new_desc = new_desc[:max_size]

        # We always add an ellipsis because at the very least
        # we chopped mid paragraph.
        description = new_desc.strip() + "…"
    return description if description else None
