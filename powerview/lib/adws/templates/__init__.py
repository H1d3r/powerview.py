NAMESPACES = {
    "ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
    "addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
    "adlq": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery",
    "da": "http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess",
    "ca": "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions",

    "soapenv": "http://www.w3.org/2003/05/soap-envelope",
    "wsa": "http://www.w3.org/2005/08/addressing",
    "wsen": "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
    "wxf": "http://schemas.xmlsoap.org/ws/2004/09/transfer",
    "xsd": "http://www.w3.org/2001/XMLSchema",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",

    "s": "http://www.w3.org/2003/05/soap-envelope",
    "a": "http://www.w3.org/2005/08/addressing",
}

LDAP_QUERY_FSTRING: str = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
    xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</a:Action>
        <ad:instance>ldap:389</ad:instance>
        <a:MessageID>urn:uuid:{uuid}</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Enumeration</a:To>
    </s:Header>
    <s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
        xmlns:adlq="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery">
        <wsen:Enumerate>
            <wsen:Filter Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery">
                <adlq:LdapQuery>
                    <adlq:Filter>{query}</adlq:Filter>
                    <adlq:BaseObject>{search_base}</adlq:BaseObject>
                    <adlq:Scope>{search_scope}</adlq:Scope>
                </adlq:LdapQuery>
            </wsen:Filter>
            <ad:Selection Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1">
                <ad:SelectionProperty>ad:distinguishedName</ad:SelectionProperty>
                {attributes}
            </ad:Selection>
        </wsen:Enumerate>
    </s:Body>
</s:Envelope>"""

LDAP_PULL_FSTRING: str = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
    xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull</a:Action>
        <ad:instance>ldap:389</ad:instance>
        <a:MessageID>urn:uuid:{uuid}</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Enumeration</a:To>
    </s:Header>
    <s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
        <wsen:Pull>
            <wsen:EnumerationContext>{enum_ctx}</wsen:EnumerationContext>
            <wsen:MaxElements>256</wsen:MaxElements>
        </wsen:Pull>
    </s:Body>
</s:Envelope>"""


LDAP_PUT_FSTRING: str = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
        xmlns:a="http://www.w3.org/2005/08/addressing"
        xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
        xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:da="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess">
        <s:Header>
            <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/transfer/Put</a:Action>
            <ad:instance>ldap:389</ad:instance>
            <ad:objectReferenceProperty>{object_ref}</ad:objectReferenceProperty>
            <da:IdentityManagementOperation s:mustUnderstand="1"
                xmlns:i="http://www.w3.org/2001/XMLSchema-instance"></da:IdentityManagementOperation>
            <a:MessageID>urn:uuid:{uuid}</a:MessageID>
            <a:ReplyTo>
                <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
            </a:ReplyTo>
            <a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Resource</a:To>
        </s:Header>
        <s:Body>
            {attributes}
        </s:Body>
    </s:Envelope>"""

LDAP_DELETE_FSTRING: str = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:xsd="http://www.w3.org/2001/XMLSchema"
            xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete</a:Action>
    <ad:instance>ldap:389</ad:instance>
    <ad:objectReferenceProperty>{object_ref}</ad:objectReferenceProperty>
    <a:MessageID>urn:uuid:{uuid}</a:MessageID>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    <a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Resource</a:To>
  </s:Header>
  <s:Body>
  </s:Body>
</s:Envelope>
"""

LDAP_ADD_FSTRING: str = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsa="http://www.w3.org/2005/08/addressing">
    <s:Header>
        <wsa:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</wsa:Action>
        <IdentityManagementOperation s:mustUnderstand="1"
            xmlns="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess" />
        <instance xmlns="http://schemas.microsoft.com/2008/1/ActiveDirectory">ldap:389</instance>
        <wsa:MessageID>urn:uuid:{uuid}</wsa:MessageID>
        <wsa:ReplyTo>
            <wsa:Address>http://www.w3.org/2005/08/addressing/anonymous</wsa:Address>
        </wsa:ReplyTo>
        <wsa:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/ResourceFactory</wsa:To>
    </s:Header>
    <s:Body>
        <AddRequest Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1"
            xmlns="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess"
            xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory"
            xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:xsd="http://www.w3.org/2001/XMLSchema">
            {attributes}
        </AddRequest>
    </s:Body>
</s:Envelope>"""

LDAP_MODIFY_DN_FSTRING: str = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/2008/1/ActiveDirectory/Data/ModifyDNRequest</a:Action>
        <ad:instance>ldap:389</ad:instance>
        <ad:objectReferenceProperty>{object_ref}</ad:objectReferenceProperty>
        <a:MessageID>urn:uuid:{uuid}</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Resource</a:To>
    </s:Header>
    <s:Body>
        <da:ModifyDNRequest xmlns:da="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data">
            <da:DistinguishedName>{object_ref}</da:DistinguishedName>
            <da:NewName>{relative_dn}</da:NewName>
            <da:DeleteOldRdn>{delete_old_rdn}</da:DeleteOldRdn>
            <da:NewParentDistinguishedName>{new_superior}</da:NewParentDistinguishedName>
        </da:ModifyDNRequest>
    </s:Body>
</s:Envelope>"""
