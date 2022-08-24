#!/usr/bin/python3

import enum
from hashlib import sha1
from dataclasses import dataclass
from zlib import adler32


class BadDexFileError(Exception):
    """Error when dex format is incorrect"""
    pass


MAGIC = b"dex\n"
ENDIAN_CONSTANT = 0x12345678
REVERSE_ENDIAN_CONSTANT = 0x78563412
NO_INDEX = 0xffffffff


class AccessFlag(enum.Flag):
    """Indicates accessibility and properties of classes and class members"""
    ACC_PUBLIC = 0x1
    ACC_PRIVATE = 0x2
    ACC_PROTECTED = 0x4
    ACC_STATIC = 0x8
    ACC_FINAL = 0x10
    ACC_SYNCHRONIZED = 0x20
    ACC_VOLATILE = 0x40
    ACC_BRIDGE = 0x40
    ACC_TRANSIENT = 0x80
    ACC_VARARGS = 0x80
    ACC_NATIVE = 0x100
    ACC_INTERFACE = 0x200
    ACC_ABSTRACT = 0x400
    ACC_STRICT = 0x800
    ACC_SYNTHETIC = 0x1000
    ACC_ANNOTATION = 0x2000
    ACC_ENUM = 0x4000
    ACC_CONSTRUCTOR = 0x10000
    ACC_DECLARED_SYNCHRONIZED = 0x20000


class TypeCode(enum.Enum):
    TYPE_HEADER_ITEM = 0x0000 # size =  0x70
    TYPE_STRING_ID_ITEM = 0x0001 # size =  0x04
    TYPE_TYPE_ID_ITEM = 0x0002 # size =  0x04
    TYPE_PROTO_ID_ITEM = 0x0003 # size =  0x0c
    TYPE_FIELD_ID_ITEM = 0x0004 # size =  0x08
    TYPE_METHOD_ID_ITEM = 0x0005 # size =  0x08
    TYPE_CLASS_DEF_ITEM = 0x0006 # size =  0x20
    TYPE_CALL_SITE_ID_ITEM = 0x0007 # size =  0x04
    TYPE_METHOD_HANDLE_ITEM = 0x0008 # size =  0x08
    TYPE_MAP_LIST = 0x1000 # size =  4 + (item.size * 12)
    TYPE_TYPE_LIST = 0x1001 # size =  4 + (item.size * 2)
    TYPE_ANNOTATION_SET_REF_LIST = 0x1002 # size =  4 + (item.size * 4)
    TYPE_ANNOTATION_SET_ITEM = 0x1003 # size =  4 + (item.size * 4)
    TYPE_CLASS_DATA_ITEM = 0x2000 # size =  implicit; must parse
    TYPE_CODE_ITEM = 0x2001 # size =  implicit; must parse
    TYPE_STRING_DATA_ITEM = 0x2002 # size =  implicit; must parse
    TYPE_DEBUG_INFO_ITEM = 0x2003 # size =  implicit; must parse
    TYPE_ANNOTATION_ITEM = 0x2004 # size =  implicit; must parse
    TYPE_ENCODED_ARRAY_ITEM = 0x2005 # size =  implicit; must parse
    TYPE_ANNOTATIONS_DIRECTORY_ITEM = 0x2006 # size =  implicit; must parse
    TYPE_HIDDENAPI_CLASS_DATA_ITEM = 0xF000 # size =  implicit; must parse


class Visibility(enum.Enum):
    VISIBILITY_BUILD = 0x00
    VISIBILITY_RUNTIME = 0x00
    VISIBILITY_SYSTEM = 0x00


class ValueFormat(enum.Enum):
    VALUE_BYTE = 0x00          # (none)          ubyte[1]    signed one-byte
    VALUE_SHORT = 0x02         # size - 1 (0…1)  ubyte[size] signed two-byte
    VALUE_CHAR = 0x03          # size - 1 (0…1)  ubyte[size] unsigned two-byte
    VALUE_INT = 0x04           # size - 1 (0…3)  ubyte[size] signed four-byte
    VALUE_LONG = 0x06          # size - 1 (0…7)  ubyte[size] signed eight-byte
    VALUE_FLOAT = 0x10         # size - 1 (0…3)  ubyte[size] IEEE754 32-bit
    VALUE_DOUBLE = 0x11        # size - 1 (0…7)  ubyte[size] IEEE754 64-bit
    VALUE_METHOD_TYPE = 0x15   # size - 1 (0…3)  ubyte[size] four-byte index proto_ids
    VALUE_METHOD_HANDLE = 0x16 # size - 1 (0…3)  ubyte[size] four-byte index method_handles
    VALUE_STRING = 0x17        # size - 1 (0…3)  ubyte[size] four-byte index string_ids
    VALUE_TYPE = 0x18          # size - 1 (0…3)  ubyte[size] four-byte index type_ids
    VALUE_FIELD = 0x19         # size - 1 (0…3)  ubyte[size] four-byte index field_ids
    VALUE_METHOD = 0x1a        # size - 1 (0…3)  ubyte[size] four-byte index method_ids
    VALUE_ENUM = 0x1b          # size - 1 (0…3)  ubyte[size] four-byte index field_ids
    VALUE_ARRAY = 0x1c         # (none)          encoded_array
    VALUE_ANNOTATION = 0x1d    # (none)          encoded_annotation
    VALUE_NULL = 0x1e          # (none)          (none)  null reference value
    VALUE_BOOLEAN = 0x1f       # boolean (0…1)   (none)


class HeaderItem:
    """Data present in header section"""
    __slots__ = ("version", "checksum", "signature", "file_size",
                 "header_size", "endianness", "link_size", "link_off",
                 "map_off", "string_ids_size", "string_ids_off",
                 "type_ids_size", "type_ids_off", "proto_ids_size",
                 "proto_ids_off", "field_ids_size", "field_ids_off",
                 "method_ids_size", "method_ids_off", "class_defs_size",
                 "class_defs_off", "data_size", "data_off")

    HEADER_SIZE = 112

    def __init__(self, data: bytes):
        magic = data[0 : 4]
        if magic != MAGIC:
            raise BadDexFileError(f"Bad magic: should start with {MAGIC.hex()}")
        self.version = data[4:7].decode("utf8")
        if data[7] != 0x00:
            raise BadDexFileError(f"Bad magic: 7th byte should be 00")

        self.checksum = adler32(data[12:])
        expected_checksum = int.from_bytes(data[8 : 12], "little")
        if self.checksum != expected_checksum:
            raise BadDexFileError(f"Checksum should be {expected_checksum:x}, not {self.checksum:x}")

        signature = data[12 : 32]
        self.signature = sha1(data[32:]).digest()
        if self.signature != signature:
            raise BadDexFileError(f"SHA1 signature should be {signature.hex()}, not {self.signature.hex()}")

        self.file_size = len(data)
        file_size = int.from_bytes(data[32 : 36], "little")
        if self.file_size != file_size:
            raise BadDexFileError(f"File size should be {file_size}, not {self.file_size}")

        header_size = int.from_bytes(data[36 : 40], "little")
        if header_size != self.HEADER_SIZE:
            raise BadDexFileError(f"File size should be {self.HEADER_SIZE}, not {header_size}")

        endian_tag = int.from_bytes(data[40 : 44], "little")
        if endian_tag == ENDIAN_CONSTANT:
            self.endianness = "big"
        elif endian_tag == REVERSE_ENDIAN_CONSTANT:
            self.endianness = "little"
        else:
            raise BadDexFileError(f"Bad endian constant ({endian_tag:#x})")

        self.link_size = int.from_bytes(data[44 : 48], "little")
        self.link_off = int.from_bytes(data[48 : 52], "little")
        self.map_off = int.from_bytes(data[52 : 56], "little")
        self.string_ids_size = int.from_bytes(data[56 : 60], "little")
        self.string_ids_off = int.from_bytes(data[60 : 64], "little")
        self.type_ids_size = int.from_bytes(data[64 : 68], "little")
        self.type_ids_off = int.from_bytes(data[68 : 72], "little")
        self.proto_ids_size = int.from_bytes(data[72 : 76], "little")
        self.proto_ids_off = int.from_bytes(data[76 : 80], "little")
        self.field_ids_size = int.from_bytes(data[80 : 84], "little")
        self.field_ids_off = int.from_bytes(data[84 : 88], "little")
        self.method_ids_size = int.from_bytes(data[88 : 92], "little")
        self.method_ids_off = int.from_bytes(data[92 : 96], "little")
        self.class_defs_size = int.from_bytes(data[96 : 100], "little")
        self.class_defs_off = int.from_bytes(data[100 : 104], "little")
        self.data_size = int.from_bytes(data[104 : 108], "little")
        self.data_off = int.from_bytes(data[108 : 112], "little")

    def dump_data(self) -> str:
        """Return a string representing the header"""
        data = "Header:\n"
        data += f"\tMagic: {MAGIC.hex()}\n"
        data += f"\tVersion: {self.version}\n"
        data += f"\tChecksum: {self.checksum:x}\n"
        data += f"\tSignature: {self.signature.hex()}\n"
        data += f"\tFile size: {self.file_size}\n"
        data += f"\tHeader size: {self.HEADER_SIZE}\n"
        data += f"\tEndianness: {self.endianness}\n"
        data += f"\tLink size: {self.link_size}\n"
        data += f"\tLink off: {self.link_off:#x}\n"
        data += f"\tMap off: {self.map_off:#x}\n"
        data += f"\tString ids size: {self.string_ids_size}\n"
        data += f"\tString ids off: {self.string_ids_off:#x}\n"
        data += f"\tType ids size: {self.type_ids_size}\n"
        data += f"\tType ids off: {self.type_ids_off:#x}\n"
        data += f"\tProto ids size: {self.proto_ids_size}\n"
        data += f"\tProto ids off: {self.proto_ids_off:#x}\n"
        data += f"\tField ids size: {self.field_ids_size}\n"
        data += f"\tField ids off: {self.field_ids_off:#x}\n"
        data += f"\tMethod ids size: {self.method_ids_size}\n"
        data += f"\tMethod ids off: {self.method_ids_off:#x}\n"
        data += f"\tClass defs size: {self.class_defs_size}\n"
        data += f"\tClass defs off: {self.class_defs_off:#x}\n"
        data += f"\tData size: {self.data_size}\n"
        data += f"\tData off: {self.data_off:#x}\n"
        return data


class MapList:
    """List of MapItem"""
    __slots__ = ("size", "list")

    def __init__(self, data: bytes):
        self.size = int.from_bytes(data[0 : 4], "little")
        self.list = [MapItem(data[off : off + 12])
                     for off in range(4, 4 + (self.size * 12), 12)]

    def dump_data(self) -> str:
        """Return a string representing the map list"""
        data = f"Map list: ({self.size} items)\n"
        for mi in self.list:
            data +="\t"
            data += "\t".join(mi.dump_data().splitlines(True))
        return data


class MapItem:
    """Data present in a map item"""
    __slots__ = ("type", "unused", "size", "offset")

    def __init__(self, data: bytes):
        self.type = TypeCode(int.from_bytes(data[0 : 2], "little"))
        self.unused = int.from_bytes(data[2 : 4], "little")
        self.size = int.from_bytes(data[4 : 8], "little")
        self.offset = int.from_bytes(data[8 : 12], "little")

    def dump_data(self) -> str:
        """Return a string representing the map list"""
        data = "Map Item:\n"
        data += f"\tType: {self.type.name}\n"
        data += f"\tSize: {self.size}\n"
        data += f"\tOffset: {self.offset:#x}\n"
        return data


class StringDataItem:
    """Data present in string data item"""
    __slots__ = ("utf16size", "data")

    def __init__(self, data: bytes):
        self.utf16size = int.from_bytes(data[0 : 1], "little")
        self.data = data[1 : 1 + self.utf16size].decode("utf8")

    def dump_data(self) -> str:
        """Return a string representing the string data item"""
        data = f"({self.utf16size})\t"
        data += self.data
        return data


class StringIdItem:
    """Data present in string id item"""
    __slots__ = ("string_data_off",)

    def __init__(self, data: bytes):
        self.string_data_off = int.from_bytes(data, "little")

    def get_string_data_item(self, data: bytes) -> StringDataItem:
        """Return the string data item corresponding to the string id item"""
        return StringDataItem(data[self.string_data_off:])

    def dump_data(self, full_data: bytes) -> str:
        """Return a string representing the string id item"""
        data = f"{self.string_data_off:#x}\t"
        data += self.get_string_data_item(full_data).dump_data()
        return data


class TypeIdItem:
    """Data present in type id item"""
    __slots__ = ("descriptor_idx",)

    def __init__(self, data):
        self.descriptor_idx = int.from_bytes(data, "little")

    def get_string_id_item(self, string_ids: list[StringIdItem]) -> StringIdItem:
        """Return the string id item corresponding to the type id item"""
        return string_ids[self.descriptor_idx]

    def dump_data(self, string_ids: list[StringIdItem],
                  full_data: bytes) -> str:
        """Return a string representing the string id item"""
        data = f"({self.descriptor_idx})\t"
        string_data = self.get_string_id_item(string_ids).get_string_data_item(full_data)
        data += f"{string_data.data}"
        return data


class TypeItem:
    """Data present in type item"""
    __slots__ = ("type_idx",)

    def __init__(self, data: bytes):
        self.type_idx = int.from_bytes(data, "little")

    def get_type_type_id_item(self, type_ids: list[TypeIdItem]) -> TypeIdItem:
        """Return the type id item corresponding to the type index"""
        return type_ids[self.type_idx]

    def dump_data(self, type_ids: list[TypeIdItem],
            string_ids: list[StringIdItem], full_data: bytes) -> str:
        """Return a string representing the type item"""
        type_ = (self.get_type_type_id_item(type_ids).
                get_string_id_item(string_ids).get_string_data_item(full_data))
        data = f"{type_.data}"
        return data


class TypeList:
    """Data present in type list"""
    __slots__ = ("size", "list")

    def __init__(self, data: bytes):
        self.size = int.from_bytes(data[0 : 4], "little")
        self.list = [TypeItem(data[off : off + 2])
                     for off in range(4, 4 + (self.size * 2), 2)]

    def dump_data(self, type_ids: list[TypeIdItem],
            string_ids: list[StringIdItem], full_data: bytes):
        """Return a string representing the type list"""
        data = f"({self.size} params) "
        data += "(" + ", ".join([t.dump_data(type_ids, string_ids, full_data)
                           for t in self.list]) + ")"
        return data


class ProtoIdItem:
    """Data present in proto id item"""
    __slots__ = ("shorty_idx", "return_type_idx", "parameters_off")

    def __init__(self, data: bytes):
        self.shorty_idx = int.from_bytes(data[0 : 4], "little")
        self.return_type_idx = int.from_bytes(data[4 : 8], "little")
        self.parameters_off = int.from_bytes(data[8 : 12], "little")

    def get_shorty_string_id_item(self, string_ids: list[StringIdItem]) -> StringIdItem:
        """Return the string id item corresponding to the shorty"""
        return string_ids[self.shorty_idx]

    def get_return_type_type_id_item(self, type_ids: list[TypeIdItem]) -> TypeIdItem:
        """Return the type id item corresponding to the return type"""
        return type_ids[self.return_type_idx]

    def get_parameters(self, data: bytes) -> TypeList:
        """Get the function parameter types"""
        if self.parameters_off == 0x00:
            return TypeList(bytes(4))
        else:
            return TypeList(data[self.parameters_off:])

    def dump_data(self, type_ids: list[TypeIdItem],
            string_ids: list[StringIdItem], full_data: bytes):
        """Return a string representing the prototype id item"""
        shorty = self.get_shorty_string_id_item(string_ids).get_string_data_item(full_data)
        data = f"({self.shorty_idx}) {shorty.data}\t"
        return_type = (self.get_return_type_type_id_item(type_ids).
                get_string_id_item(string_ids).get_string_data_item(full_data))
        data += f"({self.return_type_idx}) {return_type.data}\t"
        parameters = self.get_parameters(full_data)
        data += f"({self.parameters_off:#x})"
        data += parameters.dump_data(type_ids, string_ids, full_data)
        return data


class FieldIdItem:
    """Data present in field id item"""
    __slots__ = ("class_idx", "type_idx", "name_idx")

    def __init__(self, data: bytes):
        self.class_idx = int.from_bytes(data[0 : 2], "little")
        self.type_idx = int.from_bytes(data[2 : 4], "little")
        self.name_idx = int.from_bytes(data[4 : 8], "little")

    def get_class_type_id_item(self, type_ids: list[TypeIdItem]) -> TypeIdItem:
        """Return the type id item corresponding to the class idx"""
        return type_ids[self.class_idx]

    def get_type_type_id_item(self, type_ids: list[TypeIdItem]) -> TypeIdItem:
        """Return the type id item corresponding to the type idx"""
        return type_ids[self.type_idx]

    def get_name_string_id_item(self, string_ids: list[StringIdItem]) -> StringIdItem:
        """Return the string id item corresponding to the name idx"""
        return string_ids[self.name_idx]

    def dump_data(self, type_ids: list[TypeIdItem],
            string_ids: list[StringIdItem], full_data: bytes):
        """Return a string representing the field id item"""
        class_ = (self.get_class_type_id_item(type_ids).
                get_string_id_item(string_ids).get_string_data_item(full_data))
        data = f"({self.class_idx}) {class_.data}\t"
        type_ = (self.get_type_type_id_item(type_ids).
                get_string_id_item(string_ids).get_string_data_item(full_data))
        data += f"({self.type_idx}) {type_.data}\t"
        name = self.get_name_string_id_item(string_ids).get_string_data_item(full_data)
        data += f"({self.name_idx}) {name.data}"
        return data


class MethodIdItem:
    """Data present in method id item"""
    __slots__ = ("class_idx", "proto_idx", "name_idx")

    def __init__(self, data: bytes):
        self.class_idx = int.from_bytes(data[0 : 2], "little")
        self.proto_idx = int.from_bytes(data[2 : 4], "little")
        self.name_idx = int.from_bytes(data[4 : 8], "little")

    def get_class_type_id_item(self, type_ids: list[TypeIdItem]) -> TypeIdItem:
        """Return the type id item corresponding to the class idx"""
        return type_ids[self.class_idx]

    def get_proto_proto_id_item(self, proto_ids: list[ProtoIdItem]) -> ProtoIdItem:
        """Return the proto id item corresponding to the proto idx"""
        return proto_ids[self.proto_idx]

    def get_name_string_id_item(self, string_ids: list[StringIdItem]) -> StringIdItem:
        """Return the string id item corresponding to the name idx"""
        return string_ids[self.name_idx]

    def dump_data(self, proto_ids: list[ProtoIdItem], type_ids: list[TypeIdItem],
            string_ids: list[StringIdItem], full_data: bytes):
        """Return a string representing the method id item"""
        class_ = (self.get_class_type_id_item(type_ids).
                get_string_id_item(string_ids).get_string_data_item(full_data))
        data = f"({self.class_idx}) {class_.data}\t"
        proto = self.get_proto_proto_id_item(proto_ids)
        proto_return_type = (proto.get_return_type_type_id_item(type_ids).
                get_string_id_item(string_ids).get_string_data_item(full_data))
        data += f"({self.proto_idx}) {proto_return_type.data}\t"
        name = self.get_name_string_id_item(string_ids).get_string_data_item(full_data)
        data += f"({self.name_idx}) {name.data}\t"
        proto_param_type_list = proto.get_parameters(full_data)
        data += "(" + ", ".join([t.dump_data(type_ids, string_ids, full_data)
                           for t in proto_param_type_list.list]) + ")"
        return data


class Uleb128:
    """Represents uleb128 number type"""
    __slots__ = ("data", "_size")

    def __init__(self, data: bytes):
        size = 0
        for idx, b in enumerate(data):
            if (b & 0x80) == 0:
                size = idx + 1
                break
            if idx == 4:
                raise BadDexFileError("Uleb128 must be 5 bytes max")
        self._size = size
        self.data = data[0 : size]

    def __int__(self) -> int:
        """Convert uleb128 to int"""
        value = 0
        for b in reversed(self.data):
            value = (value << 7) | (b & 0x7f)
        return value


class EncodedValue:
    """Data present in annotation element"""
    __slots__ = ("value_arg", "value_type", "value")

    def __init__(self, data: bytes):
        self.value_type = ValueFormat(data[0] & 0x1f)
        self.value_arg = (data[0] & 0xe0 >> 5)
        if self.value_type is ValueFormat.VALUE_BYTE:
            if self.value_arg != 0:
                raise BadDexFileError("Value arg for BYTE should be 0")
            self.value = int.from_bytes(data[1:2], "little", signed=True)
        elif self.value_type is ValueFormat.VALUE_SHORT:
        # size - 1 (0…1)  ubyte[size] signed two-byte
            size = self.value_arg + 1

        elif self.value_type is ValueFormat.VALUE_CHAR:
            pass
        # size - 1 (0…1)  ubyte[size] unsigned two-byte
        elif self.value_type is ValueFormat.VALUE_INT:
            pass
        # size - 1 (0…3)  ubyte[size] signed four-byte
        elif self.value_type is ValueFormat.VALUE_LONG:
            pass
        # size - 1 (0…7)  ubyte[size] signed eight-byte
        elif self.value_type is ValueFormat.VALUE_FLOAT:
            pass
        # size - 1 (0…3)  ubyte[size] IEEE754 32-bit
        elif self.value_type is ValueFormat.VALUE_DOUBLE:
            pass
        # size - 1 (0…7)  ubyte[size] IEEE754 64-bit
        elif self.value_type is ValueFormat.VALUE_METHOD_TYPE:
            pass
        # size - 1 (0…3)  ubyte[size] four-byte index proto_ids
        elif self.value_type is ValueFormat.VALUE_METHOD_HANDLE:
            pass
        # size - 1 (0…3)  ubyte[size] four-byte index method_handles
        elif self.value_type is ValueFormat.VALUE_STRING:
            pass
        # size - 1 (0…3)  ubyte[size] four-byte index string_ids
        elif self.value_type is ValueFormat.VALUE_TYPE:
            pass
        # size - 1 (0…3)  ubyte[size] four-byte index type_ids
        elif self.value_type is ValueFormat.VALUE_FIELD:
            pass
        # size - 1 (0…3)  ubyte[size] four-byte index field_ids
        elif self.value_type is ValueFormat.VALUE_METHOD:
            pass
        # size - 1 (0…3)  ubyte[size] four-byte index method_ids
        elif self.value_type is ValueFormat.VALUE_ENUM:
            pass
        # size - 1 (0…3)  ubyte[size] four-byte index field_ids
        elif self.value_type is ValueFormat.VALUE_ARRAY:
            pass
        # (none)          encoded_array
        elif self.value_type is ValueFormat.VALUE_ANNOTATION:
            pass
        # (none)          encoded_annotation
        elif self.value_type is ValueFormat.VALUE_NULL:
            pass
        # (none)          (none)  null reference value
        elif self.value_type is ValueFormat.VALUE_BOOLEAN:
            pass
        # boolean (0…1)   (none)



class AnnotationElement:
    """Data present in annotation element"""
    __slots__ = ("name_idx", "value")

    def __init__(self, data: bytes):
        self.name_idx = Uleb128(data[0:])
        off = len(self.name_idx.get_bytes())
        self.value = EncodedValue(data[off:])


class EncodedAnnotation:
    """Data present in encoded annotation format"""
    __slots__ = ("type_idx", "size", "elements")

    def __init__(self, data: bytes):
        self.type_idx = Uleb128(data[0:])
        off = len(self.type_idx.get_bytes())
        self.size = Uleb128(data[off:])
        off += len(self.size.get_bytes())
        self.elements = []
        for _ in range(self.size):
            self.elements.append(AnnotationElement(data[off:]))
            off += len(self.elements[-1].get_bytes())

class AnnotationItem:
    """Data present in annotation item"""
    __slots__ = ("visibility", "annotation")

    def __init__(self, data: bytes):
        self.visibility = Visibility(int.from_bytes(data[0 : 1], "little"))
        self.annotation = EncodedAnnotation(data[1:])


class AnnotationOffItem:
    """Data present in annotation off item"""
    __slots__ = ("annotation_off",)

    def __init__(self, data: bytes):
        self.annotations_off = int.from_bytes(data[0 : 4], "little")

    def get_annotations(self, full_data: bytes) -> AnnotationItem:
        return AnnotationItem[self.annotations_off:]


class AnnotationSetItem:
    """Data present in annotation set item"""
    __slots__ = ("size", "entries")

    def __init__(self, data: bytes):
        self.size = int.from_bytes(data[0 : 4], "little")
        self.entries = [AnnotationOffItem(data[off : off + 4])
                        for off in range(4, 4 + (self.size * 4), 4)]


class FieldAnnotation:
    """Data present in field annotation"""
    __slots__ = ("field_idx", "annotations_off")

    def __init__(self, data: bytes):
        self.field_idx = int.from_bytes(data[0 : 4], "little")
        self.annotations_off = int.from_bytes(data[4 : 8], "little")

    def get_field(self, field_ids: list[FieldIdItem]) -> FieldIdItem:
        return field_ids[self.field_idx]

    def get_annotations(self, data: bytes):
        return AnnotationSetItem(data[self.annotations_off:])

    def dump_data(self, field_ids: list[FieldIdItem], full_data: bytes) -> str:
        """Return a string representing the field annotation"""
        field = (self.get_field(field_ids).get_string_id_item(string_ids).
                get_string_data_item(full_data).data)
        data = field + ": "
        data += self.get_annotations(full_data).dump_data()
        return data


class AnnotationDirectoryItem:
    """Data present in annotation directory item"""
    __slots__ = ("class_annotations_off", "fields_size",
                 "annoted_methods_size", "annoted_parameters_size",
                 "field_annotations", "method_annotations",
                 "parameter_annotations")

    def __init__(self, data: bytes):
        self.class_annotations_off = int.from_bytes(data[0 : 4], "little")
        self.fields_size = int.from_bytes(data[4 : 8], "little")
        self.annoted_methods_size = int.from_bytes(data[8 : 12], "little")
        self.annoted_parameters_size = int.from_bytes(data[12 : 16], "little")
        start = 16
        end = start + (self.fields_size * 8)
        self.field_annotations = [FieldAnnotation(data[off: off + 8])
                                  for off in range(start, end, 8)]
        start = end
        end = start + (self.annoted_methods_size * 8)
        self.method_annotations = [MethodAnnotation(data[off: off + 8])
                                   for off in range(start, end, 8)]
        start = end
        end = start + (self.annoted_parameters_size * 8)
        self.parameter_annotations = [ParameterAnnotation(data[off: off + 8])
                                      for off in range(start, end, 8)]

    def dump_data(self) -> str:
        """Return a string representing the annotation directory item"""
        data = "A"
        return data


class EncodedField:
    """Data present in encoded field format"""
    __slots__ = ("field_idx_diff", "access_flags", "_size")

    def __init__(self, data: bytes):
        self.field_idx_diff = Uleb128(data[0:])
        off = self.field_idx_diff._size
        self.access_flags = Uleb128(data[off:])
        self._size = off + self.access_flags._size

    def get_field(self, prev_idx: int, field_ids: list[FieldIdItem]) -> FieldIdItem:
        field_idx = prev_idx + int(self.field_idx_diff)
        return field_ids[field_idx]

    def get_access_flags(self) -> AccessFlag:
        return AccessFlag(int(self.access_flags))

    def dump_data(self, prev_idx: int, field_ids: list[FieldIdItem],
            string_ids: list[StringIdItem], full_data: bytes) -> str:
        field = (self.get_field(prev_idx, field_ids).get_name_string_id_item(string_ids).
            get_string_data_item(full_data).data)
        data = f"({int(self.field_idx_diff)}) {field}\t"
        data += f"{self.get_access_flags()}"
        return data


class EncodedMethod:
    """Data present in encoded method format"""
    __slots__ = ("method_idx_diff", "access_flags", "code_off", "_size")

    def __init__(self, data: bytes):
        self.method_idx_diff = Uleb128(data[0:])
        off = self.method_idx_diff._size
        self.access_flags = Uleb128(data[off:])
        off = off + self.access_flags._size
        self.code_off = Uleb128(data[off:])
        self._size = off + self.code_off._size

    def get_method(self, prev_idx: int, method_ids: list[MethodIdItem]) -> MethodIdItem:
        method_idx = prev_idx + int(self.method_idx_diff)
        return method_ids[method_idx]

    def get_access_flags(self) -> AccessFlag:
        return AccessFlag(int(self.access_flags))

    def dump_data(self, prev_idx: int, method_ids: list[MethodIdItem],
            string_ids: list[StringIdItem], full_data: bytes) -> str:
        method = (self.get_method(prev_idx, method_ids).get_name_string_id_item(string_ids).
            get_string_data_item(full_data).data)
        data = f"({int(self.method_idx_diff)}) {method}\t"
        data += f"{self.get_access_flags()}\t{int(self.code_off):#x}"
        return data


class ClassDataItem:
    """Data present in class data item"""
    __slots__ = ("static_fields_size", "instance_fields_size",
                 "direct_mehtods_size", "virtual_methods_size",
                 "static_fields", "instance_fields", "direct_mehtods",
                 "virtual_methods")

    def __init__(self, data: bytes):
        self.static_fields_size = Uleb128(data[0:])
        off = self.static_fields_size._size
        self.instance_fields_size = Uleb128(data[off:])
        off += self.instance_fields_size._size
        self.direct_mehtods_size = Uleb128(data[off:])
        off += self.direct_mehtods_size._size
        self.virtual_methods_size = Uleb128(data[off:])
        off += self.virtual_methods_size._size
        self.static_fields = []
        for _ in range(int(self.static_fields_size)):
            self.static_fields.append(EncodedField(data[off:]))
            off += self.static_fields[-1]._size
        self.instance_fields = []
        for _ in range(int(self.instance_fields_size)):
            self.instance_fields.append(EncodedField(data[off:]))
            off += self.instance_fields[-1]._size
        self.direct_mehtods = []
        for _ in range(int(self.direct_mehtods_size)):
            self.direct_mehtods.append(EncodedMethod(data[off:]))
            off += self.direct_mehtods[-1]._size
        self.virtual_methods = []
        for _ in range(int(self.virtual_methods_size)):
            self.virtual_methods.append(EncodedMethod(data[off:]))
            off += self.virtual_methods[-1]._size

    def dump_data(self, method_ids: list[MethodIdItem], field_ids: list[FieldIdItem],
            proto_ids: list[ProtoIdItem], type_ids: list[TypeIdItem],
            string_ids: list[StringIdItem], full_data: bytes) -> str:
        """Return a string representing the class data item"""
        data = f"Static fields: ({int(self.static_fields_size)})\n"
        prev_idx = 0
        for f in self.static_fields:
            data += f"\t{f.dump_data(prev_idx, field_ids, string_ids, full_data)}\n"
            prev_idx += int(f.field_idx_diff)
        prev_idx = 0
        data += f"Instance fields: ({int(self.instance_fields_size)})\n"
        for f in self.instance_fields:
            data += f"\t{f.dump_data(prev_idx, field_ids, string_ids, full_data)}\n"
            prev_idx += int(f.field_idx_diff)
        prev_idx = 0
        data += f"Direct methods: ({int(self.direct_mehtods_size)})\n"
        for m in self.direct_mehtods:
            data += f"\t{m.dump_data(prev_idx, method_ids, string_ids, full_data)}\n"
            prev_idx += int(m.method_idx_diff)
        prev_idx = 0
        data += f"Virtual methods: ({int(self.virtual_methods_size)})\n"
        for m in self.virtual_methods:
            data += f"\t{m.dump_data(prev_idx, method_ids, string_ids, full_data)}\n"
            prev_idx += int(m.method_idx_diff)
        return data


class EncodedArrayItem:
    """Data present in class data item"""
    __slots__ = ("a",)

    def __init__(self, data: bytes):
        pass

    def dump_data(self) -> str:
        """Return a string representing the encoded array item"""
        data = "E"
        return data


class ClassDefItem:
    """Data present in class def item"""
    __slots__ = ("class_idx", "access_flags", "superclass_idx",
                 "interfaces_off", "source_file_idx", "annotations_off",
                 "class_data_off", "static_values_off")

    def __init__(self, data: bytes):
        self.class_idx = int.from_bytes(data[0 : 4], "little")
        self.access_flags = AccessFlag(int.from_bytes(data[4 : 8], "little"))
        self.superclass_idx = int.from_bytes(data[8 : 12], "little")
        self.interfaces_off = int.from_bytes(data[12 : 16], "little")
        self.source_file_idx = int.from_bytes(data[16 : 20], "little")
        self.annotations_off = int.from_bytes(data[20 : 24], "little")
        self.class_data_off = int.from_bytes(data[24 : 28], "little")
        self.static_values_off = int.from_bytes(data[28 : 32], "little")

    def get_class_type_id_item(self, type_ids: list[TypeIdItem]) -> TypeIdItem:
        """Return the type id item corresponding to the class idx"""
        return type_ids[self.class_idx]

    def get_superclass_type_id_item(self, type_ids: list[TypeIdItem]) -> TypeIdItem | None:
        """Return the type id item corresponding to the superclass idx"""
        if self.superclass_idx == NO_INDEX:
            return None
        else:
            return type_ids[self.superclass_idx]

    def get_interfaces_type_list(self, data: bytes) -> TypeList | None:
        """Return the type list corresponding to the interface off"""
        if self.interfaces_off == 0x00:
            return None
        else:
            return TypeList(data[self.interfaces_off:])

    def get_source_file_string_id_item(self, string_ids: list[StringIdItem]) -> StringIdItem | None:
        """Return the string id item corresponding to the source file idx"""
        if self.source_file_idx == NO_INDEX:
            return None
        else:
            return string_ids[self.source_file_idx]

    def get_annotations_annotation_directory_item(self, data: bytes) -> AnnotationDirectoryItem | None:
        """Return the annotation directory item corresponding to the annotation off"""
        if self.annotations_off == 0x00:
            return None
        else:
            return AnnotationDirectoryItem(data[self.annotations_off:])

    def get_class_data_class_data_item(self, data: bytes) -> ClassDataItem | None:
        """Return the class data item corresponding to the class data off"""
        if self.class_data_off == 0x00:
            return None
        else:
            return ClassDataItem(data[self.class_data_off:])

    def get_static_values_encoded_array_item(self, data: bytes) -> EncodedArrayItem | None:
        """Return the enocoded array item corresponding to the static values off"""
        if self.static_values_off == 0x00:
            return None
        else:
            return EncodedArrayItem(data[self.static_values_off:])

    def dump_data(self, method_ids: list[MethodIdItem], field_ids: list[FieldIdItem],
            proto_ids: list[ProtoIdItem], type_ids: list[TypeIdItem],
            string_ids: list[StringIdItem], full_data: bytes):
        """Return a string representing the class def item"""
        class_ = self.get_class_type_id_item(type_ids).get_string_id_item(string_ids).get_string_data_item(full_data)
        data = f"Class: ({self.class_idx}) {class_.data}\n"
        data += f"Access flags: {self.access_flags}\n"
        superclass = self.get_superclass_type_id_item(type_ids)
        data += f"Superclass: ({self.superclass_idx}) "
        if superclass is None:
            data += "None\n"
        else:
            data += superclass.get_string_id_item(string_ids).get_string_data_item(full_data).data + "\n"
        interfaces = self.get_interfaces_type_list(full_data)
        data += f"\nInterfaces: ({self.interfaces_off:#x}) "
        if interfaces is None:
            data += "None\n"
        else:
            data += interfaces.dump_data(type_ids, string_ids, full_data) + "\n"
        source_file = self.get_source_file_string_id_item(string_ids)
        data += f"Source file: ({self.source_file_idx}) "
        if source_file is None:
            data += "None\n"
        else:
            data += source_file.get_string_data_item(full_data).data + "\n"
        annotations = self.get_annotations_annotation_directory_item(full_data)
        data += f"Annotations: ({self.annotations_off:#x}) "
        if annotations is None:
            data += "None\n"
        else:
            data += annotations.dump_data() + "\n"
        class_data = self.get_class_data_class_data_item(full_data)
        data += f"Class data: ({self.class_data_off:#x}) "
        if class_data is None:
            data += "None\n"
        else:
            dump = class_data.dump_data(method_ids, field_ids, proto_ids,
                type_ids, string_ids, full_data)
            data += "\n\t" + "\t".join(dump.splitlines(True)) + "\n"
        static_values = self.get_static_values_encoded_array_item(full_data)
        data += f"Static values: ({self.interfaces_off:#x}) "
        if static_values is None:
            data += "None\n"
        else:
            data += static_values.dump_data() + "\n"
        data += "\n"
        return data


class DexParser:
    """Parse dex binary data"""
    __slots__ = ("full_data", "header", "map_list", "string_ids", "type_ids",
                 "proto_ids", "field_ids", "method_ids", "class_defs")

    EXPECTED_HEADER_SIZE = 112
    ENDIAN_CONSTANT = b"\x12\x34\x56\x78"
    REVERSE_ENDIAN_CONSTANT = b"\x78\x56\x34\x12"


    def __init__(self, data: bytes):
        self.full_data = data
        self.header = HeaderItem(data)
        self.map_list = MapList(data[self.header.map_off:])

        start = self.header.string_ids_off
        size = self.header.string_ids_size
        self.string_ids = [StringIdItem(data[off : off + 4])
            for off in range(start,  start + (size * 4), 4)]

        start = self.header.type_ids_off
        size = self.header.type_ids_size
        self.type_ids = [TypeIdItem(data[off : off + 4])
            for off in range(start,  start + (size * 4), 4)]

        start = self.header.proto_ids_off
        size = self.header.proto_ids_size
        self.proto_ids = [ProtoIdItem(data[off : off + 12])
            for off in range(start,  start + (size * 12), 12)]

        start = self.header.field_ids_off
        size = self.header.field_ids_size
        self.field_ids = [FieldIdItem(data[off : off + 8])
            for off in range(start,  start + (size * 8), 8)]

        start = self.header.method_ids_off
        size = self.header.method_ids_size
        self.method_ids = [MethodIdItem(data[off : off + 8])
            for off in range(start,  start + (size * 8), 8)]

        start = self.header.class_defs_off
        size = self.header.class_defs_size
        self.class_defs = [ClassDefItem(data[off : off + 32])
            for off in range(start,  start + (size * 32), 32)]

    def print_all(self) -> None:
        """Print all parsed informations"""
        print(self.header.dump_data())
        print(self.map_list.dump_data())
        print(self.dump_all_strings())
        print(self.dump_all_types())
        print(self.dump_all_prototypes())
        print(self.dump_all_fields())
        print(self.dump_all_methods())
        print(self.dump_all_class_defs())

    def dump_all_strings(self) -> str:
        data = "Strings:\n"
        for s in self.string_ids:
            data += f"\t{s.dump_data(self.full_data)}\n"
        return data

    def dump_all_types(self) -> str:
        data = "Types:\n"
        for t in self.type_ids:
            data += f"\t{t.dump_data(self.string_ids, self.full_data)}\n"
        return data

    def dump_all_prototypes(self) -> str:
        data = "Prototypes:\n"
        for p in self.proto_ids:
            data += f"\t{p.dump_data(self.type_ids, self.string_ids, self.full_data)}\n"
        return data

    def dump_all_fields(self) -> str:
        data = "Fields:\n"
        for f in self.field_ids:
            data += f"\t{f.dump_data(self.type_ids, self.string_ids, self.full_data)}\n"
        return data

    def dump_all_methods(self) -> str:
        data = "Methods:\n"
        for m in self.method_ids:
            data += f"\t{m.dump_data(self.proto_ids, self.type_ids, self.string_ids, self.full_data)}\n"
        return data

    def dump_all_class_defs(self) -> str:
        data = "Class defs:\n"
        for c in self.class_defs:
            dump = c.dump_data(self.method_ids, self.field_ids, self.proto_ids,
                self.type_ids, self.string_ids, self.full_data)
            dump = "\t".join(dump.splitlines(True))
            data += f"\t{dump}\n"
        return data


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <file.dex>")
        return 64

    with open(argv[1], "rb") as f:
        data = f.read()

    dex = DexParser(data)
    dex.print_all()
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv))
