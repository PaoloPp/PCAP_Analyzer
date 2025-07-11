import base64
import constants as c

def process_data_pckt(_pckt, _no):
    pckt_data = {}
    pckt_data = {
        "Time": int(_pckt.time),
        "Pckt_No": _no,
        "Data": base64.b64encode(_pckt["Raw"].load) if _pckt.haslayer('Raw') else None
    }
    return pckt_data

def process_pckt(_pckt, _no):
    pckt_data = {}
    if _pckt.haslayer('TCP'):
        pckt_data = {
            "Time": int(_pckt.time),
            "No": _no,
            "SourceIP": _pckt["IP"].src if _pckt.haslayer('IP') else "",
            "DestinationIP": _pckt["IP"].dst if _pckt.haslayer('IP') else "",
            "SourcePort": int(_pckt["TCP"].sport) if _pckt.haslayer('TCP') else 0,
            "DestinationPort": int(_pckt["TCP"].dport) if _pckt.haslayer('TCP') else 0,
            "SequenceNumber": int(_pckt["TCP"].seq) if _pckt.haslayer('TCP') else 0,
            "AcknowledgementNumber": int(_pckt["TCP"].ack) if _pckt.haslayer('TCP') else 0,
            "Protocol": get_protocol_name(_pckt["IP"].proto) if _pckt.haslayer('IP') else "",
            "Length": int(_pckt["IP"].len) if _pckt.haslayer('IP') else 0,
            "Load": base64.b64encode(_pckt["Raw"].load).decode('utf-8') if _pckt.haslayer('Raw') else ""
        }
    elif _pckt.haslayer('UDP'):
        pckt_data = {
            "Time": int(_pckt.time),
            "No": _no,
            "SourceIP": _pckt["IP"].src if _pckt.haslayer('IP') else "",
            "DestinationIP": _pckt["IP"].dst if _pckt.haslayer('IP') else "",
            "SourcePort": int(_pckt["UDP"].sport) if _pckt.haslayer('UDP') else 0,
            "DestinationPort": int(_pckt["UDP"].dport) if _pckt.haslayer('UDP') else 0,
            "SequenceNumber": 0,  # TCP-only field
            "AcknowledgementNumber": 0,  # TCP-only field
            "Protocol": get_protocol_name(_pckt["IP"].proto) if _pckt.haslayer('IP') else "",
            "Length": int(_pckt["IP"].len) if _pckt.haslayer('IP') else 0,
            "Load": base64.b64encode(_pckt["Raw"].load).decode('utf-8') if _pckt.haslayer('Raw') else ""
        }
    return pckt_data

def process_metadata_payload(_pckt, _no):
    pckt_metadata = {}
    pckt_payload = {}
    if _pckt.haslayer('TCP'):
        pckt_metadata = {
            "Time": int(_pckt.time),
            "No": _no,
            "SourceIP": _pckt["IP"].src if _pckt.haslayer('IP') else "",
            "DestinationIP": _pckt["IP"].dst if _pckt.haslayer('IP') else "",
            "SourcePort": int(_pckt["TCP"].sport) if _pckt.haslayer('TCP') else 0,
            "DestinationPort": int(_pckt["TCP"].dport) if _pckt.haslayer('TCP') else 0,
            "SequenceNumber": int(_pckt["TCP"].seq) if _pckt.haslayer('TCP') else 0,
            "AcknowledgementNumber": int(_pckt["TCP"].ack) if _pckt.haslayer('TCP') else 0,
            "Protocol": get_protocol_name(_pckt["IP"].proto) if _pckt.haslayer('IP') else "",
            "Length": int(_pckt["IP"].len) if _pckt.haslayer('IP') else 0,
        }
    elif _pckt.haslayer('UDP'):
        pckt_metadata = {
            "Time": int(_pckt.time),
            "No": _no,
            "SourceIP": _pckt["IP"].src if _pckt.haslayer('IP') else "",
            "DestinationIP": _pckt["IP"].dst if _pckt.haslayer('IP') else "",
            "SourcePort": int(_pckt["UDP"].sport) if _pckt.haslayer('UDP') else 0,
            "DestinationPort": int(_pckt["UDP"].dport) if _pckt.haslayer('UDP') else 0,
            "SequenceNumber": 0,  # TCP-only field
            "AcknowledgementNumber": 0,  # TCP-only field
            "Protocol": get_protocol_name(_pckt["IP"].proto) if _pckt.haslayer('IP') else "",
            "Length": int(_pckt["IP"].len) if _pckt.haslayer('IP') else 0,
        }
    pckt_payload = {
            "No": _no,
            "Length": int(_pckt["IP"].len) if _pckt.haslayer('IP') else 0,
            "Load": base64.b64encode(_pckt["Raw"].load).decode('utf-8') if _pckt.haslayer('Raw') else ""
        }
    
    return pckt_metadata, pckt_payload

def get_protocol_name(protocol_number):
    return c.protocol_mapping.get(protocol_number, "Unknown")