# KA-APSI

KA-APSI is a C++ implementation of an Authorized Private Set Intersection (APSI) protocol. This protocol enables two parties (receiver and sender) to privately compute the intersection of their input sets with authorization features. It supports different network modes optimized for LAN and WAN. 

## Building

To build the project, simply run: 

`make `

This will compile the executable `bin/apsi`.

## Usage

Run the APSI executable with the following syntax:

`bin/apsi <receiver input size> <sender input size> --mode <lan|wan>`

### Example

For receiver and sender input sizes of 256 using LAN mode:

`bin/apsi 256 256 --mode lan` 

For WAN mode:

`bin/apsi 256 256 --mode wan` 


## License

This project is licensed under the MIT license.


