from ..templates import LDAP_QUERY_FSTRING, LDAP_PULL_FSTRING, NAMESPACES
from ..error import ADWSError
from powerview.utils.helpers import IDict

from uuid import uuid4
from xml.etree import ElementTree
import base64
import logging

def xml_to_dict(xml_string: str, attributes: list[str] = None) -> dict:
    try:
        root = ElementTree.fromstring(xml_string)
        result = {}
        entries = []
        
        # Convert attributes to lowercase for case-insensitive comparison
        attributes_lower = [attr.lower() for attr in attributes] if attributes else None
        
        header = root.find(".//{http://www.w3.org/2003/05/soap-envelope}Header") or root.find(".//s:Header", NAMESPACES)
        if header is not None:
            for child in header:
                tag = child.tag.split("}")[-1]
                if child.text and child.text.strip():
                    result[tag] = child.text.strip()
        
        fault = root.find(".//soapenv:Fault", NAMESPACES) or root.find(".//s:Fault", NAMESPACES)
        if fault:
            code = fault.find(".//soapenv:Value", NAMESPACES) or fault.find(".//s:Value", NAMESPACES)
            if code is not None and code.text:
                result["FaultCode"] = code.text
            
            subcode = fault.find(".//soapenv:Subcode/soapenv:Value", NAMESPACES) or fault.find(".//s:Subcode/s:Value", NAMESPACES)
            if subcode is not None and subcode.text:
                result["FaultSubcode"] = subcode.text
            
            reason = fault.find(".//soapenv:Text", NAMESPACES) or fault.find(".//s:Text", NAMESPACES)
            if reason is not None and reason.text:
                result["Error"] = reason.text
            
            detail = root.find(".//soapenv:Detail", NAMESPACES) or root.find(".//s:Detail", NAMESPACES)
            if detail is not None:
                detail_dict = {}
                def parse_element(element, current_dict):
                    for sub_element in element:
                        sub_tag = sub_element.tag.split("}")[-1]
                        if sub_element.text:
                            current_dict[sub_tag] = sub_element.text
                        elif len(sub_element) > 0:
                            nested_dict = {}
                            parse_element(sub_element, nested_dict)
                            current_dict[sub_tag] = nested_dict
                parse_element(detail, detail_dict)
                result["ErrorDetail"] = detail_dict
            
        enum_context = root.find(".//wsen:EnumerationContext", NAMESPACES)
        if enum_context is not None and enum_context.text:
            result["EnumerationContext"] = enum_context.text
        
        expires = root.find(".//wsen:Expires", NAMESPACES)
        if expires is not None and expires.text:
            result["Expires"] = expires.text
        
        end_of_sequence = root.find(".//wsen:EndOfSequence", NAMESPACES)
        if end_of_sequence is not None:
            result["EndOfSequence"] = True
        
        items = root.findall(".//wsen:Items/*", NAMESPACES)
        for obj in items:
            entry_dn = None
            attributes_dict = {}
            raw_attributes_dict = {}
            
            dn_element = obj.find(".//ad:distinguishedName/ad:value", NAMESPACES)
            if dn_element is not None and dn_element.text:
                entry_dn = dn_element.text
            
            for attr in obj:
                attr_tag = attr.tag.split("}")[-1]
                
                if attributes and attr_tag.lower() not in attributes_lower:
                    continue
                    
                ldap_syntax = attr.attrib.get('LdapSyntax', '')
                values = []
                raw_values = []
                
                for val in attr.findall(".//ad:value", NAMESPACES):
                    if val.text is None:
                        continue
                        
                    raw_value_str = val.text
                    raw_value_bytes = raw_value_str.encode('utf-8')
                    
                    value = raw_value_str
                    xsi_type = val.get("{http://www.w3.org/2001/XMLSchema-instance}type")
                    
                    if xsi_type == "xsd:base64Binary":
                        try:
                            value = base64.b64decode(raw_value_str + '==')
                        except base64.binascii.Error:
                            logging.warning(f"Failed to decode base64 value for {attr_tag}: {raw_value_str}")
                            value = raw_value_bytes
                    elif xsi_type and xsi_type.lower() == 'xsd:integer':
                        try:
                            value = int(raw_value_str)
                        except Exception:
                            pass
                    elif ldap_syntax == 'integer':
                        try:
                            value = int(raw_value_str)
                        except Exception:
                            pass
                    
                    values.append(value)
                    raw_values.append(raw_value_bytes)
                
                if values:
                    if attr_tag not in attributes_dict:
                        attributes_dict[attr_tag] = values[0] if len(values) == 1 else values
                        raw_attributes_dict[attr_tag] = raw_values[0] if len(raw_values) == 1 else raw_values
            
            if entry_dn is None:
                if 'distinguishedName' in attributes_dict:
                    entry_dn = attributes_dict['distinguishedName']
                else:
                    fallback_id = next(iter(raw_attributes_dict.values())) if raw_attributes_dict else str(uuid4())
                    if isinstance(fallback_id, bytes):
                        try:
                            fallback_id = fallback_id.decode('utf-8', errors='ignore')
                        except:
                            fallback_id = str(uuid4())
                    entry_dn = f"Object_{fallback_id}"
            
            entries.append({
                'dn': entry_dn,
                'attributes': IDict(attributes_dict),
                'raw_attributes': IDict(raw_attributes_dict),
                'type': 'searchResEntry'
            })
        
        if entries:
            result["entries"] = entries
        
        if not result:
            raise ValueError("was unable to parse xml from the server response")
        
        return result
    except Exception as e:
        return {"Error": str(e), "RawXML": xml_string[:200] + "..." if len(xml_string) > 200 else xml_string}

def handle_str_to_xml(xmlstr):
    """Takes an xml string and returns an Element of the root
        node of an xml object.
    Also deals with error and faults in the response

    Args:
        xmlstr (str): str form of xml data

    Returns:
        Element: xml object
    """

    # Check for fault markers more reliably
    is_fault = ":Fault>" in xmlstr and (":Reason>" in xmlstr or ":Detail>" in xmlstr)
    if not is_fault:
        return ElementTree.fromstring(xmlstr)

    def manually_cut_out_fault(xml_str: str) -> str:
        """cut out the fault text description using
        slices.  This is dirty and not certain but
        if it cant be parsed with xml parsers, its
        all we have.

        Args:
            xml_str (str): str of xml data

        Returns:
            str: the fault msg
        """
        starttag = xml_str.find(":Text") + len(":Text")
        endtag = xml_str[starttag:].find(":Text")
        return xml_str[starttag : starttag + endtag]

    et: ElementTree.Element | None = None
    try:
        et = ElementTree.fromstring(xmlstr)
    except ElementTree.ParseError:
        # If parsing fails, raise ADWSError with the raw string
        raise ADWSError(xmlstr)

    base_msg = str()

    fault = et.find(".//soapenv:Fault", namespaces=NAMESPACES)
    if not fault:  # maybe there isnt actually anything erroring?
        if not et:
                raise ValueError("was unable to parse xml from the server response")
        return et

    reason = fault.find(".//soapenv:Text", namespaces=NAMESPACES)
    base_msg += reason.text if reason is not None else ""  # type: ignore

    detail = fault.find(".//soapenv:Detail", namespaces=NAMESPACES)
    if detail is not None:
        ElementTree.indent(detail)
        detail_xmlstr = (
            ElementTree.tostring(detail, encoding="unicode")
            if detail is not None
            else ""
        )
    else:
        detail_xmlstr = ""

    # Raise ADWSError with the combined message or raw XML if parsing occurred
    # ADWSError constructor will handle finding the specific <ad:Error>
    raise ADWSError(xmlstr) # Pass the original XML string to the custom handler

def search_operation(fqdn,
                    search_base,
                    search_filter,
                    search_scope,
                    attributes
                    ):
    fAttributes: str = ""
    for attr in attributes:
        fAttributes += (
            "<ad:SelectionProperty>addata:{attr}</ad:SelectionProperty>\n".format(
                attr=attr
            )
        )
    
    query_vars = {
        "uuid": str(uuid4()),
        "fqdn": fqdn,
        "query": search_filter,
        "attributes": fAttributes,
        "search_base": search_base,
        "search_scope": search_scope
    }

    return LDAP_QUERY_FSTRING.format(**query_vars)

def handle_enum_ctx(fqdn: str, enum_ctx: str):
    """
    Handle the enumeration context from the server.
    """
    _vars = {
        "uuid": str(uuid4()),
        "fqdn": fqdn,
        "enum_ctx": enum_ctx,
    }

    return LDAP_PULL_FSTRING.format(**_vars)
