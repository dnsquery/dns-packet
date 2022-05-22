export type RecordClass = "IN" | "CS" | "CH" | "HS" | "ANY" | string;
export function toString (type: number): RecordClass;
export function toType (name: RecordClass): number;
