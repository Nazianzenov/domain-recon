// Minimal typings for the parts of spark-md5 we use (avoids an extra @types dependency).
declare module 'spark-md5' {
  interface SparkMD5ArrayBufferStatic {
    hash(buffer: ArrayBuffer, raw?: false): string;
  }
  interface SparkMD5Static {
    hash(str: string, raw?: false): string;
    ArrayBuffer: SparkMD5ArrayBufferStatic;
  }
  const SparkMD5: SparkMD5Static;
  export default SparkMD5;
}
