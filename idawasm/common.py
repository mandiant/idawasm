import collections


def offset_of(struc, fieldname):
    '''
    given a wasm struct instance and a field name, return the offset into the struct where you'd find the field.
    '''
    p = 0
    dec_meta = struc.get_decoder_meta()
    for field in struc.get_meta().fields:
        if field.name != fieldname:
            p += dec_meta['lengths'][field.name]
        else:
            return p
    raise KeyError('field not found: ' + fieldname)


def size_of(struc, fieldname=None):
    '''
    given a wasm struct instance, compute the size of the element.
    if a field name is provided, fetch the size of the given field.
    otherwise, fetch the size of the entire struct.
    '''
    if fieldname is not None:
        # size of the given field, by name
        dec_meta = struc.get_decoder_meta()
        return dec_meta['lengths'][fieldname]
    else:
        # size of the entire given struct
        return sum(struc.get_decoder_meta()['lengths'].values())


Field = collections.namedtuple('Field', ['offset', 'name', 'size', 'value'])


def get_fields(struc):
    p = 0
    dec_meta = struc.get_decoder_meta()
    for field in struc.get_meta().fields:
        flen = dec_meta['lengths'][field.name]
        if flen > 0:
            yield Field(p, field.name, flen, getattr(struc, field.name))
        p += flen


def struc_to_dict(struc):
    return {
        f.name: f.value for f in get_fields(struc)
    }
