// ID is a byte array with
// [  type  | root_genesis | checksum ]
// [2 bytes |   27 bytes   | 2 bytes  ]
// where the root_genesis are the first 28 bytes from the hash root_genesis

export class Id {

    constructor(typ, genesis) {
        const checksum = Core.CalculateChecksum(typ, genesis)
        this.bytes = [...typ, ...checksum]
    }

    string(){
return 
    }

}

// String returns a base58 from the ID
func(id * ID) String() string {
    return base58.Encode(id[:])
}

// Bytes returns the bytes from the ID
func(id * ID) Bytes()[]byte {
    return id[:]
}

func(id * ID) BigInt() * big.Int {
    var idElem merkletree.ElemBytes
    copy(idElem[:], id[:])
    return idElem.BigInt()
}

func(id * ID) Equal(id2 * ID) bool {
    return bytes.Equal(id[:], id2[:])
}

// func (id ID) MarshalJSON() ([]byte, error) {
//         fmt.Println(id.String())
//         return json.Marshal(id.String())
// }

func(id ID) MarshalText()([]byte, error) {
    // return json.Marshal(id.String())
    return []byte(id.String()), nil
}

func(id * ID) UnmarshalText(b[]byte) error {
    var err error
    var idFromString ID
    idFromString, err = IDFromString(string(b))
    copy(id[:], idFromString[:])
    return err
}

func(id * ID) Equals(id2 * ID) bool {
    return bytes.Equal(id[:], id2[:])
}
