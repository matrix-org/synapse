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
import codecs
import logging
import re
from typing import (
    TYPE_CHECKING,
    Callable,
    Dict,
    Generator,
    Iterable,
    List,
    Optional,
    Set,
    Union,
)

if TYPE_CHECKING:
    from lxml import etree

logger = logging.getLogger(__name__)

_charset_match = re.compile(
    rb'<\s*meta[^>]*charset\s*=\s*"?([a-z0-9_-]+)"?', flags=re.I
)
_xml_encoding_match = re.compile(
    rb'\s*<\s*\?\s*xml[^>]*encoding="([a-z0-9_-]+)"', flags=re.I
)
_content_type_match = re.compile(r'.*; *charset="?(.*?)"?(;|$)', flags=re.I)

# Certain elements aren't meant for display.
ARIA_ROLES_TO_IGNORE = {"directory", "menu", "menubar", "toolbar"}


def _normalise_encoding(encoding: str) -> Optional[str]:
    """Use the Python codec's name as the normalised entry."""
    try:
        return codecs.lookup(encoding).name
    except LookupError:
        return None


def _get_html_media_encodings(
    body: bytes, content_type: Optional[str]
) -> Iterable[str]:
    """
    Get potential encoding of the body based on the (presumably) HTML body or the content-type header.

    The precedence used for finding a character encoding is:

    1. <meta> tag with a charset declared.
    2. The XML document's character encoding attribute.
    3. The Content-Type header.
    4. Fallback to utf-8.
    5. Fallback to windows-1252.

    This roughly follows the algorithm used by BeautifulSoup's bs4.dammit.EncodingDetector.

    Args:
        body: The HTML document, as bytes.
        content_type: The Content-Type header.

    Returns:
        The character encoding of the body, as a string.
    """
    # There's no point in returning an encoding more than once.
    attempted_encodings: Set[str] = set()

    # Limit searches to the first 1kb, since it ought to be at the top.
    body_start = body[:1024]

    # Check if it has an encoding set in a meta tag.
    match = _charset_match.search(body_start)
    if match:
        encoding = _normalise_encoding(match.group(1).decode("ascii"))
        if encoding:
            attempted_encodings.add(encoding)
            yield encoding

    # TODO Support <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>

    # Check if it has an XML document with an encoding.
    match = _xml_encoding_match.match(body_start)
    if match:
        encoding = _normalise_encoding(match.group(1).decode("ascii"))
        if encoding and encoding not in attempted_encodings:
            attempted_encodings.add(encoding)
            yield encoding

    # Check the HTTP Content-Type header for a character set.
    if content_type:
        content_match = _content_type_match.match(content_type)
        if content_match:
            encoding = _normalise_encoding(content_match.group(1))
            if encoding and encoding not in attempted_encodings:
                attempted_encodings.add(encoding)
                yield encoding

    # Finally, fallback to UTF-8, then windows-1252.
    for fallback in ("utf-8", "cp1252"):
        if fallback not in attempted_encodings:
            yield fallback


def decode_body(
    body: bytes, uri: str, content_type: Optional[str] = None
) -> Optional["etree.Element"]:
    """
    This uses lxml to parse the HTML document.

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

    # The idea here is that multiple encodings are tried until one works.
    # Unfortunately the result is never used and then LXML will decode the string
    # again with the found encoding.
    for encoding in _get_html_media_encodings(body, content_type):
        try:
            body.decode(encoding)
        except Exception:
            pass
        else:
            break
    else:
        logger.warning("Unable to decode HTML body for %s", uri)
        return None

    from lxml import etree

    # Create an HTML parser.
    parser = etree.HTMLParser(recover=True, encoding=encoding)

    # Attempt to parse the body. Returns None if the body was successfully
    # parsed, but no tree was found.
    return etree.fromstring(body, parser)


def _get_meta_tags(
    tree: "etree.Element",
    property: str,
    prefix: str,
    property_mapper: Optional[Callable[[str], Optional[str]]] = None,
) -> Dict[str, Optional[str]]:
    """
    Search for meta tags prefixed with a particular string.

    Args:
        tree: The parsed HTML document.
        property: The name of the property which contains the tag name, e.g.
            "property" for Open Graph.
        prefix: The prefix on the property to search for, e.g. "og" for Open Graph.
        property_mapper: An optional callable to map the property to the Open Graph
            form. Can return None for a key to ignore that key.

    Returns:
        A map of tag name to value.
    """
    results: Dict[str, Optional[str]] = {}
    for tag in tree.xpath(
        f"//*/meta[starts-with(@{property}, '{prefix}:')][@content][not(@content='')]"
    ):
        # if we've got more than 50 tags, someone is taking the piss
        if len(results) >= 50:
            logger.warning(
                "Skipping parsing of Open Graph for page with too many '%s:' tags",
                prefix,
            )
            return {}

        key = tag.attrib[property]
        if property_mapper:
            key = property_mapper(key)
            # None is a special value used to ignore a value.
            if key is None:
                continue

        results[key] = tag.attrib["content"]

    return results


def _map_twitter_to_open_graph(key: str) -> Optional[str]:
    """
    Map a Twitter card property to the analogous Open Graph property.

    Args:
        key: The Twitter card property (starts with "twitter:").

    Returns:
        The Open Graph property (starts with "og:") or None to have this property
        be ignored.
    """
    # Twitter card properties with no analogous Open Graph property.
    if key == "twitter:card" or key == "twitter:creator":
        return None
    if key == "twitter:site":
        return "og:site_name"
    # Otherwise, swap twitter to og.
    return "og" + key[7:]


def parse_html_to_open_graph(tree: "etree.Element") -> Dict[str, Optional[str]]:
    """
    Parse the HTML document into an Open Graph response.

    This uses lxml to search the HTML document for Open Graph data (or
    synthesizes it from the document).

    Args:
        tree: The parsed HTML document.

    Returns:
        The Open Graph response as a dictionary.
    """

    # Search for Open Graph (og:) meta tags, e.g.:
    #
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

    og = _get_meta_tags(tree, "property", "og")

    # TODO: Search for properties specific to the different Open Graph types,
    # such as article: meta tags, e.g.:
    #
    # "article:publisher" : "https://www.facebook.com/thethudonline" />
    # "article:author" content="https://www.facebook.com/thethudonline" />
    # "article:tag" content="baby" />
    # "article:section" content="Breaking News" />
    # "article:published_time" content="2016-03-31T19:58:24+00:00" />
    # "article:modified_time" content="2016-04-01T18:31:53+00:00" />

    # Search for Twitter Card (twitter:) meta tags, e.g.:
    #
    # "twitter:site"    : "@matrixdotorg"
    # "twitter:creator" : "@matrixdotorg"
    #
    # Twitter cards tags also duplicate Open Graph tags.
    #
    # See https://developer.twitter.com/en/docs/twitter-for-websites/cards/guides/getting-started
    twitter = _get_meta_tags(tree, "name", "twitter", _map_twitter_to_open_graph)
    # Merge the Twitter values with the Open Graph values, but do not overwrite
    # information from Open Graph tags.
    for key, value in twitter.items():
        if key not in og:
            og[key] = value

    if "og:title" not in og:
        # Attempt to find a title from the title tag, or the biggest header on the page.
        title = tree.xpath("((//title)[1] | (//h1)[1] | (//h2)[1] | (//h3)[1])/text()")
        if title:
            og["og:title"] = title[0].strip()
        else:
            og["og:title"] = None

    if "og:image" not in og:
        meta_image = tree.xpath(
            "//*/meta[translate(@itemprop, 'IMAGE', 'image')='image'][not(@content='')]/@content[1]"
        )
        # If a meta image is found, use it.
        if meta_image:
            og["og:image"] = meta_image[0]
        else:
            # Try to find images which are larger than 10px by 10px.
            #
            # TODO: consider inlined CSS styles as well as width & height attribs
            images = tree.xpath("//img[@src][number(@width)>10][number(@height)>10]")
            images = sorted(
                images,
                key=lambda i: (
                    -1 * float(i.attrib["width"]) * float(i.attrib["height"])
                ),
            )
            # If no images were found, try to find *any* images.
            if not images:
                images = tree.xpath("//img[@src][1]")
            if images:
                og["og:image"] = images[0].attrib["src"]

            # Finally, fallback to the favicon if nothing else.
            else:
                favicons = tree.xpath("//link[@href][contains(@rel, 'icon')]/@href[1]")
                if favicons:
                    og["og:image"] = favicons[0]

    if "og:description" not in og:
        # Check the first meta description tag for content.
        meta_description = tree.xpath(
            "//*/meta[translate(@name, 'DESCRIPTION', 'description')='description'][not(@content='')]/@content[1]"
        )
        # If a meta description is found with content, use it.
        if meta_description:
            og["og:description"] = meta_description[0]
        else:
            og["og:description"] = parse_html_description(tree)
    elif og["og:description"]:
        # This must be a non-empty string at this point.
        assert isinstance(og["og:description"], str)
        og["og:description"] = summarize_paragraphs([og["og:description"]])

    # TODO: delete the url downloads to stop diskfilling,
    # as we only ever cared about its OG
    return og


def parse_html_description(tree: "etree.Element") -> Optional[str]:
    """
    Calculate a text description based on an HTML document.

    Grabs any text nodes which are inside the <body/> tag, unless they are within
    an HTML5 semantic markup tag (<header/>, <nav/>, <aside/>, <footer/>), or
    if they are within a <script/>, <svg/> or <style/> tag, or if they are within
    a tag whose content is usually only shown to old browsers
    (<iframe/>, <video/>, <canvas/>, <picture/>).

    This is a very very very coarse approximation to a plain text render of the page.

    Args:
        tree: The parsed HTML document.

    Returns:
        The plain text description, or None if one cannot be generated.
    """
    # We don't just use XPATH here as that is slow on some machines.

    from lxml import etree

    TAGS_TO_REMOVE = {
        "header",
        "nav",
        "aside",
        "footer",
        "script",
        "noscript",
        "style",
        "svg",
        "iframe",
        "video",
        "canvas",
        "img",
        "picture",
        etree.Comment,
    }

    # Split all the text nodes into paragraphs (by splitting on new
    # lines)
    text_nodes = (
        re.sub(r"\s+", "\n", el).strip()
        for el in _iterate_over_text(tree.find("body"), TAGS_TO_REMOVE)
    )
    return summarize_paragraphs(text_nodes)


def _iterate_over_text(
    tree: Optional["etree.Element"],
    tags_to_ignore: Set[Union[str, "etree.Comment"]],
    stack_limit: int = 1024,
) -> Generator[str, None, None]:
    """Iterate over the tree returning text nodes in a depth first fashion,
    skipping text nodes inside certain tags.

    Args:
        tree: The parent element to iterate. Can be None if there isn't one.
        tags_to_ignore: Set of tags to ignore
        stack_limit: Maximum stack size limit for depth-first traversal.
            Nodes will be dropped if this limit is hit, which may truncate the
            textual result.
            Intended to limit the maximum working memory when generating a preview.
    """

    if tree is None:
        return

    # This is a stack whose items are elements to iterate over *or* strings
    # to be returned.
    elements: List[Union[str, "etree.Element"]] = [tree]
    while elements:
        el = elements.pop()

        if isinstance(el, str):
            yield el
        elif el.tag not in tags_to_ignore:
            # If the element isn't meant for display, ignore it.
            if el.get("role") in ARIA_ROLES_TO_IGNORE:
                continue

            # el.text is the text before the first child, so we can immediately
            # return it if the text exists.
            if el.text:
                yield el.text

            # We add to the stack all the element's children, interspersed with
            # each child's tail text (if it exists).
            #
            # We iterate in reverse order so that earlier pieces of text appear
            # closer to the top of the stack.
            for child in el.iterchildren(reversed=True):
                if len(elements) > stack_limit:
                    # We've hit our limit for working memory
                    break

                if child.tail:
                    # The tail text of a node is text that comes *after* the node,
                    # so we always include it even if we ignore the child node.
                    elements.append(child.tail)

                elements.append(child)


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
