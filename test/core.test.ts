import { Core } from '@lib/core/core';
import { Id } from '@lib/core/id';

test('test id parsers', () => {
  const typ0Hex = Uint8Array.from([0, 0]);
  const genesis032bytes = Core.hashBytes('genesistest');
  const genesis0 = genesis032bytes.slice(0, 27);
  const id0 = new Id(typ0Hex, genesis0);
  expect('114vgnnCupQMX4wqUBjg5kUya3zMXfPmKc9HNH4TSE').toEqual(id0.string());

  const typ1 = new Uint8Array(Core.hexToBytes('0001'));
  const genesis132bytes = Core.hashBytes('genesistest');
  const genesis1 = genesis132bytes.slice(0, 27);
  const id1 = new Id(typ1, genesis1);
  expect('1GYjyJKqdDyzo927FqJkAdLWB64kV2NVAjaQFHbAf').toEqual(id1.string());

  const id0FromBytes = Id.idFromBytes(id0.bytes());
  expect(id0.bytes()).toEqual(id0FromBytes.bytes());
  expect(id0.string()).toEqual(id0FromBytes.string());
  expect('114vgnnCupQMX4wqUBjg5kUya3zMXfPmKc9HNH4TSE').toEqual(
    id0FromBytes.string(),
  );

  const id1FromBytes = Id.idFromBytes(id1.bytes());
  expect(id1.bytes()).toEqual(id1FromBytes.bytes());
  expect(id1.string()).toEqual(id1FromBytes.string());
  expect('1GYjyJKqdDyzo927FqJkAdLWB64kV2NVAjaQFHbAf').toEqual(
    id1FromBytes.string(),
  );

  const id0FromString = Id.idFromString(id0.string());
  expect(id0.bytes()).toEqual(id0FromString.bytes());
  expect(id0.string()).toEqual(id0FromString.string());
  expect('114vgnnCupQMX4wqUBjg5kUya3zMXfPmKc9HNH4TSE').toEqual(
    id0FromBytes.string(),
  );
});

test('test id from big int', () => {
  const id = Id.idFromString('11AVZrKNJVqDJoyKrdyaAgEynyBEjksV5z2NjZoPxf');

  const idBigInt = id.bigInt();

  expect(
    402932821512301734229101344062340840386673288679225668308579568895363448832n,
  ).toEqual(idBigInt);

  const got = Id.idFromInt(idBigInt);

  expect(id).toEqual(got);
});
