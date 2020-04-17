from argparse import Namespace
from lxml import etree


class CVRF_Syntax(object):
    # CVRF Elements and Namespaces.

    cvrf_versions = ["1.1", "1.2"]
   

    VULN_ARGS = [
        "all",
        "Title",
        "ID",
        "Notes",
        "DiscoveryDate",
        "ReleaseDate",
        "Involvements",
        "CVE",
        "CWE",
        "ProductID",
        "ProductStatuses",
        "Threats",
        "CVSSScoreSets",
        "Remediations",
        "References",
        "Acknowledgments",
        "Vulnerability",
    ]

    def __init__(self, cvrf_version):
        # defaults to current cvrf version 1.2 specification unless otherwise
        # specified
        self.CVRF_SCHEMA = "http://docs.oasis-open.org/csaf/csaf-cvrf/v1.2/cs01/schemas/cvrf.xsd"
        self.NAMESPACES = {
            x.upper(): "{http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/%s}" % x
            for x in ("cvrf", "vuln", "prod")
        }
        self.CVRF_CATALOG = "schemata/catalog_1_2.xml"
        self.CVRF_SCHEMA_FILE = "schemata/cvrf/1.2/cvrf.xsd"

        if cvrf_version == "1.1":
            self.CVRF_SCHEMA = "http://www.icasi.org/CVRF/schema/cvrf/1.1/cvrf.xsd"
            self.NAMESPACES = {
                x.upper(): "{http://www.icasi.org/CVRF/schema/%s/1.1}" % x
                for x in ("cvrf", "vuln", "prod")
            }
            self.CVRF_CATALOG = "schemata/catalog_1_1.xml"
            self.CVRF_SCHEMA_FILE = "schemata/cvrf/1.1/cvrf.xsd"


def get_partial_key_in_dict(key, dict):
    for k, v in dict.items():
        if k.startswith(key):
            return k
    return None


def chop_ns_prefix(element):
    """
    Return the element of a fully qualified namespace URI

    element: a fully qualified ET element tag
    """
    return element[element.rindex("}") + 1:]


def get_vulnerability_node(node):
    while node is not None:
        if chop_ns_prefix(node.tag) == "Vulnerability":
            return node
        node = node.getparent()
    return node


def is_productid_node(node):
    if node is not None:
        tag = chop_ns_prefix(node.tag)
        if tag == "ProductID":
            return True
    return False


def has_child_product_nodes(node):
    # get the nodes children and check to see if it contains ProductID nodes
    children = node.getchildren()
    for child in children:
        tag = chop_ns_prefix(child.tag)
        if tag == "ProductID":
            return True
    return False


def has_child_product_node(node, current_node):
    # get the nodes children and check to see if it contains the node matching
    # specific ProductID
    children = node.getchildren()
    for child in children:
        tag = chop_ns_prefix(child.tag)
        if tag == "ProductID":
            if child.text.strip() == current_node.text.strip():
                return True
    return False


def is_vuln_ns(node, cvrf_version):
    tag = chop_ns_prefix(node.tag)
    ns = node.tag.replace(tag, "")

    if CVRF_Syntax(cvrf_version).NAMESPACES["VULN"] == ns:
        return True
    else:
        return False


def get_product_name_node(cvrf_doc, cvrf_version, product_id):
    # Constrain Xpath search to the ProductTree container
    for node in cvrf_doc.findall(
        ".//" + CVRF_Syntax(cvrf_version).NAMESPACES["PROD"] + "ProductTree"
    ):
        for child in node.iter():
            if child.attrib and "ProductID" in child.attrib:
                if child.attrib["ProductID"] == product_id:
                    return child
    return None


def get_related_producttree_values(node, values, current_product_node, cvrf_doc):
    if node is not None:

        # climb the xpath node tree to the top capturing all the node values
        while node.getparent() is not None:

            # add values for current node
            if node.tag and node.text and node.attrib:
                tag = chop_ns_prefix(node.tag)

                text = []
                for key in node.attrib:
                    text.append(key + ":" + node.attrib[key])

                if node.text:
                    if len(node.text.strip()) > 0:
                        text.append(node.text.strip())

                text = "|".join(text)
                if text:
                    if tag in values:
                        if isinstance(values[tag], list):
                            values[tag].append(text)
                        else:
                            values[tag] = [values[tag], text]
                    else:
                        values[tag] = text

            # climb the tree
            node = node.getparent()

    return values


def get_related_vulnerability_values(node, values, current_product_node, cvrf_doc):
    if node is not None:
        children = node.getchildren()
        child_index = 0

        for child in children:
            child_index += 1

            # skip productid nodes
            if is_productid_node(child):
                continue

            # process the child if no children or has children specific
            # properties for product
            process_child = False
            if len(child.getchildren()) == 0:  # element has no children, applies to all elements
                process_child = True

            if has_child_product_nodes(child):
                if has_child_product_node(child, current_product_node):
                    process_child = True  # has children and applies to desired product id
            else:
                process_child = (
                    True  # has children but not for specific product, applies to all elements
                )

            if not process_child:
                continue

            if child.tag and child.attrib:
                tag = chop_ns_prefix(child.tag) + "_" + \
                    chop_ns_prefix(child.getparent().tag)

                text = []
                for key in child.attrib:
                    text.append(key + ":" + child.attrib[key])

                if child.text:
                    if len(child.text.strip()) > 0:
                        text.append(child.text.strip())

                text = "|".join(text)
                if text:
                    if tag in values:
                        if isinstance(values[tag], list):
                            values[tag].append(text)
                        else:
                            values[tag] = [values[tag], text]
                    else:
                        values[tag] = text

            if child.tag and child.text and not child.attrib:
                tag = chop_ns_prefix(child.tag) + "_" + \
                    chop_ns_prefix(child.getparent().tag)
                child_tag = chop_ns_prefix(child.tag)
                parent_tag = chop_ns_prefix(child.getparent().tag)
                text = child.text.strip()

                if text:
                    # put all elements with same parent tag together
                    parent_key = get_partial_key_in_dict(parent_tag, values)
                    if parent_key is not None:
                        if not isinstance(values[parent_key], list):
                            values[parent_key] += "|" + child_tag + ":" + text
                        else:
                            values[parent_key][-1] += "|" + \
                                child_tag + ":" + text
                    else:
                        # convert to list when multiple elements exist for same
                        # tag
                        if tag in values:
                            if isinstance(values[tag], list):
                                values[tag].append(text)
                            else:
                                values[tag] = [values[tag], text]
                        else:
                            values[tag] = text

            # recursively get the values for the child
            values = get_related_vulnerability_values(
                child, values, current_product_node, cvrf_doc)

        # include the current product id
        if current_product_node.tag and current_product_node.text:
            tag = chop_ns_prefix(current_product_node.tag)
            text = current_product_node.text.strip()
            values[tag] = text

    return values


def get_vulnerability_ordinal(node):
    ordinal = 0
    while node is not None:
        if chop_ns_prefix(node.tag) == "Vulnerability":
            ordinal = node.attrib["Ordinal"]
        node = node.getparent()
    return ordinal


def post_process_arglist(arg, namespace, valid_args, cvrf_version):
    parsables = []

    if CVRF_Syntax(cvrf_version).NAMESPACES[namespace] + "all" in arg:
        for element in valid_args:
            parsables.append(CVRF_Syntax(
                cvrf_version).NAMESPACES[namespace] + element)
        parsables.remove(CVRF_Syntax(
            cvrf_version).NAMESPACES[namespace] + "all")
    else:
        for element in arg:
            parsables.append(element)

    return parsables


def cvrf_parse(cvrf_doc, parsables, args, cvrf_version):
    """
    Parse a cvrf_doc and return a list of elements as determined by parsables

    cvrf_doc: the serialized CVRF ElementTree object
    parsables: list of elements to parse from a CVRF doc
    returns: a dictionary of the format {filename:[item, ...]}
    """
    items = []
    ordinal_products = {}

    for element in parsables:
        for node in cvrf_doc.iter(element):
            for child in node.iter():

                # process vuln productid elements uniquely by productid?
                if is_vuln_ns(child, cvrf_version):
                    if is_productid_node(child) and args.unique_products:
                        ordinal = get_vulnerability_ordinal(child)
                        if ordinal not in ordinal_products:
                            ordinal_products[ordinal] = []

                        product_id = child.text.strip() if child.text else ""
                        if product_id not in ordinal_products[ordinal]:
                            ordinal_products[ordinal].append(product_id)
                            items.append(child)
                    else:
                        # capture all non-productid elements
                        items.append(child)
                else:
                    # capture all non-vuln ns elements
                    items.append(child)

    # Hardcoded output for now, eventually make this user-tunable
    return items  # "stdout"


def get_data_from_node(cvrf_doc, cvrf_version, node):
    """
    Print each XML node

    node: the ElementTree node to be printed
    strip_ns: boolean that when true indicates the namespace prefix will be chomped
    f: the file to print to (default is stdout)
    """

    related_values = {}

    # should we collect related product elements data?  (for vuln prod
    # elements only)
    if is_vuln_ns(node, cvrf_version) and is_productid_node(node):
        vuln_root_node = get_vulnerability_node(node)
        related_values = get_related_vulnerability_values(
            vuln_root_node, related_values, node, cvrf_doc
        )
        product_node = get_product_name_node(
            cvrf_doc, cvrf_version, node.text.strip())
        related_values = get_related_producttree_values(
            product_node, related_values, node, cvrf_doc
        )
        return related_values


def get_data_dict_from_url(url, cvrf_version="1.1"):

    file_name = url.split("/")[-1]
    if cvrf_version == "1.1":
        vuln = ["{http://www.icasi.org/CVRF/schema/vuln/1.1}all"]

    elif cvrf_version == "1.2":
        vuln = ["{http://www.icasi.org/CVRF/schema/vuln/1.2}all"]

    schema = "schemata/cvrf/{}/cvrf.xsd".format(cvrf_version)
    args = Namespace(
        cvrf_version=cvrf_version,
        file=file_name,
        include_related_product_elements=True,
        related_product_tags=["all"],
        schema=schema,
        unique_products=True,
        vuln=vuln,
    )
    try:
        doc = etree.parse(url, etree.XMLParser(encoding="utf-8"))
        parsables = list(
            post_process_arglist(
                args.vuln, "VULN", CVRF_Syntax(
                    cvrf_version).VULN_ARGS, cvrf_version
            )
        )
        results = cvrf_parse(doc, parsables, args, cvrf_version)
        for result in results:
            if get_data_from_node(doc, cvrf_version, result):
                yield get_data_from_node(doc, cvrf_version, result)
    except BaseException:
        pass
