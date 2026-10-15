"""CAPWAP message types, element types and name tables (RFC 5415/5416 + H3C).

Copyright (c) 2026  Wang Jian
"""


class MsgType:
    """CAPWAP control message types (RFC 5415 4.5 + H3C vendor types)."""

    DISC_REQ = 1
    DISC_RESP = 2
    JOIN_REQ = 3
    JOIN_RESP = 4
    CONFIG_STATUS_REQ = 5
    CONFIG_STATUS_RESP = 6
    CONFIG_UPDATE_REQ = 7
    CONFIG_UPDATE_RESP = 8
    WTP_EVENT_REQ = 9
    WTP_EVENT_RESP = 10
    CHANGE_STATE_EV_REQ = 11
    CHANGE_STATE_EV_RESP = 12
    ECHO_REQ = 13
    ECHO_RESP = 14
    IMAGE_DATA_REQ = 15
    IMAGE_DATA_RESP = 16
    RESET_REQ = 17
    RESET_RESP = 18
    PRIMARY_DISC_REQ = 19
    PRIMARY_DISC_RESP = 20
    DATA_TRANSFER_REQ = 21
    DATA_TRANSFER_RESP = 22
    CLEAR_CONFIG_REQ = 23
    CLEAR_CONFIG_RESP = 24
    STATION_CONFIG_REQ = 25
    STATION_CONFIG_RESP = 26
    # H3C AX60 vendor message types.
    WTP_CHAN_UTIL_REQ = 145
    WTP_CHAN_UTIL_RESP = 146


MSG_NAMES = {
    1: "Discovery Request",
    2: "Discovery Response",
    3: "Join Request",
    4: "Join Response",
    5: "Configuration Status Request",
    6: "Configuration Status Response",
    7: "Configuration Update Request",
    8: "Configuration Update Response",
    9: "WTP Event Request",
    10: "WTP Event Response",
    11: "Change State Event Request",
    12: "Change State Event Response",
    13: "Echo Request",
    14: "Echo Response",
    15: "Image Data Request",
    16: "Image Data Response",
    17: "Reset Request",
    18: "Reset Response",
    19: "Primary Discovery Request",
    20: "Primary Discovery Response",
    21: "Data Transfer Request",
    22: "Data Transfer Response",
    23: "Clear Configuration Request",
    24: "Clear Configuration Response",
    25: "Station Configuration Request",
    26: "Station Configuration Response",
    145: "Chan Util Report (H3C)",
    146: "Chan Util Ack (H3C)",
}


class MsgElemType:
    """CAPWAP message element types (RFC 5415 4.6, 802.11 binding, H3C)."""

    AC_DESCRIPTOR = 1
    AC_IPV4_LIST = 2
    AC_IPV6_LIST = 3
    AC_NAME = 4
    AC_NAME_WITH_PRIORITY = 5
    AC_TIMESTAMP = 6
    ADD_MAC_ACL_ENTRY = 7
    ADD_STATION = 8
    CAPWAP_CTRL_IPV4_ADDR = 10
    CAPWAP_CTRL_IPV6_ADDR = 11
    CAPWAP_TIMERS = 12
    DATA_TRANSFER_DATA = 13
    DATA_TRANSFER_MODE = 14
    DECRYPT_ERR_REPORT = 15
    DECRYPT_ERR_REPORT_PERIOD = 16
    DEL_MAC_ACL_ENTRY = 17
    DEL_STATION = 18
    DISC_TYPE = 20
    DUPLICATE_IPV4_ADDR = 21
    DUPLICATE_IPV6_ADDR = 22
    IDLE_TIMEOUT = 23
    IMAGE_DATA = 24
    IMAGE_ID = 25
    IMAGE_INFO = 26
    INIT_DOWNLOAD = 27
    LOCATION_DATA = 28
    MAX_MESSAGE_LEN = 29
    CAPWAP_LOCAL_IPV4_ADDR = 30
    RADIO_ADMIN_STATE = 31
    RADIO_OP_STATE = 32
    RESULT_CODE = 33
    RETURNED_MESSAGE_ELEMENT = 34
    SESSION_ID = 35
    STATS_TIMER = 36
    VENDOR_SPECIFIC_PAYLOAD = 37
    WTP_BOARD_DATA = 38
    WTP_DESCRIPTOR = 39
    WTP_FALLBACK = 40
    WTP_FRAME_TUNNEL_MODE = 41
    WTP_MAC_TYPE = 44
    WTP_NAME = 45
    WTP_RADIO_STATS = 47
    WTP_REBOOT_STATS = 48
    WTP_STATIC_IP_ADDR_INFO = 49
    CAPWAP_LOCAL_IPV6_ADDR = 50
    CAPWAP_TRANSPORT_PROTO = 51
    MTU_DISC_PADDING = 52
    ECN_SUPPORT = 53
    # RFC 5416 IEEE 802.11 binding elements.
    MAC_OPERATION = 1041
    STATION_EVENT_TYPE = 1046
    WTP_RADIO_INFO = 1048
    WTP_RADIO_CONFIG = 1049
    WTP_RADIO_CAPS = 1050
    # H3C AX60 vendor elements.
    H3C_AC_PRIVATE = 0x418
    H3C_WLAN_CFG = 0xFDE8
    H3C_CHAN_UTIL = 0xFE20


ELEM_NAMES = {
    1: "AC Descriptor",
    2: "AC IPv4 List",
    3: "AC IPv6 List",
    4: "AC Name",
    5: "AC Name w/ Priority",
    10: "CAPWAP Control IPv4 Address",
    11: "CAPWAP Control IPv6 Address",
    12: "CAPWAP Timers",
    20: "Discovery Type",
    28: "Location Data",
    29: "Max Message Length",
    30: "CAPWAP Local IPv4 Address",
    31: "Radio Administrative State",
    32: "Radio Operational State",
    33: "Result Code",
    35: "Session ID",
    36: "Statistics Timer",
    38: "WTP Board Data",
    39: "WTP Descriptor",
    41: "WTP Frame Tunnel Mode",
    44: "WTP MAC Type",
    45: "WTP Name",
    47: "WTP Radio Statistics",
    48: "WTP Reboot Statistics",
    49: "WTP Static IP Address Info",
    50: "CAPWAP Local IPv6 Address",
    51: "CAPWAP Transport Protocol",
    53: "ECN Support",
    1041: "MAC Operation",
    1046: "Station Event Type",
    1048: "WTP Radio Information",
    1049: "WTP Radio Configuration",
    1050: "WTP Radio Capabilities",
    0x418: "H3C AC Private",
    0xFDE8: "H3C WLAN Config",
    0xFE20: "H3C Chan Util",
}


def msg_name(mtype):
    return MSG_NAMES.get(mtype, f"type {mtype}")


def elem_name(tag):
    return ELEM_NAMES.get(tag, f"0x{tag:04x}")
