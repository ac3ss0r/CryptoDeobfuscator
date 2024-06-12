using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

namespace CryptoDeobfuscator {
    public class Deobfuscator {

        public static MemberRef FindRefByMd(ModuleDefMD module, uint mdToken) {
            return module.GetMemberRefs().FirstOrDefault(memberRef => memberRef.MDToken.Raw == mdToken);
        }

        public static void ReplaceCalls(ModuleDefMD module, MethodDef x, MemberRef y, OpCode callType) {
            foreach (var type in module.GetTypes()) {
                foreach (var mtd in type.Methods.Where(m => m.HasBody)) {
                    foreach (var inst in mtd.Body.Instructions) {
                        if ((inst.OpCode == OpCodes.Call ||
                            inst.OpCode == OpCodes.Callvirt) && inst.Operand == x) {
                            inst.OpCode = callType;
                            inst.Operand = y;
                        }
                    }
                }
            }
        }

        static void Main(string[] args) {

            if (args.Length != 1) {
                Console.WriteLine("usage: CryptoDeobfuscator.exe file.exe");
                return;
            }

            try {
                byte[] rawData = File.ReadAllBytes(args[0]);
                var module = ModuleDefMD.Load(rawData);

                var asmResolver = new AssemblyResolver {
                    EnableTypeDefCache = true
                };
                asmResolver.AddToCache(module);

                var resolver = new Resolver(asmResolver);

                // Resolve hidden calls by refs
                foreach (var type in module.GetTypes().ToList()) {
                    if (!type.IsDelegate) continue;

                    var staticCctor = type.FindStaticConstructor();
                    if (staticCctor == null || !staticCctor.HasBody) continue;

                    var body = staticCctor.Body.Instructions;
                    if (!(body[0].IsLdcI4() && body[1].IsLdcI4() && body[2].IsLdcI4() && body[3].OpCode == OpCodes.Call)) continue;

                    var invokeMtd = type.FindMethod("Invoke");
                    var proxyMtd = type.Methods.FirstOrDefault(m => m.HasBody && m.Body.Instructions.Any(x => x.OpCode == OpCodes.Call && x.Operand == invokeMtd));

                    if (proxyMtd == null) continue;

                    var targetMethodRef = FindRefByMd(module, (uint)body[1].GetLdcI4Value());
                    if (targetMethodRef == null) continue;


                    var targetMethodDef = resolver.ResolveMethod(targetMethodRef);
                    if (targetMethodDef == null) continue;

                    Console.WriteLine("Resolved: " + targetMethodDef);

                    OpCode callType = targetMethodDef.IsConstructor ? OpCodes.Newobj :
                                      targetMethodDef.IsStatic ? OpCodes.Call : OpCodes.Callvirt;

                    ReplaceCalls(module, proxyMtd, targetMethodRef, callType);

                    module.Types.Remove(type);
                }

                try {
                    var assembly = Assembly.Load(rawData);

                    foreach (var type in module.GetTypes()) {
                        // We detect if the current type is one of the decryption types by refs in cctor
                        var staticCCtor = type.FindStaticConstructor();
                        if (staticCCtor == null || !staticCCtor.Body.HasInstructions)
                            continue;
                        List<string> references = new List<string>() { "FromBase64String", "GetExecutingAssembly",
                                                                        "GetManifestResourceStream" };
                        foreach (var instr in staticCCtor.Body.Instructions) {
                            if (instr.OpCode == OpCodes.Call || instr.OpCode == OpCodes.Callvirt) {
                                if (instr.Operand is MemberRef target)
                                    references.Remove(target.Name);
                            }
                        }

                        if (references.Count == 0) {
                            Type decryptType = assembly.GetType(type.ReflectionFullName);

                            // Decrypt strings
                            MethodDef stringDecryptMtd = type.Methods.FirstOrDefault(x => x.ReturnType == module.CorLibTypes.String && x.Parameters.Count == 1 && x.Parameters[0].Type == module.CorLibTypes.Int32);
                            if (stringDecryptMtd != null) {
                                MethodInfo reflectiveStringDecrypt = decryptType.GetMethod(stringDecryptMtd.Name, BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
                                foreach (var type2 in module.Types) {
                                    foreach (var mtd in type2.Methods) {
                                        if (!mtd.HasBody)
                                            continue;
                                        for (int i = 0; i < mtd.Body.Instructions.Count; i++) {
                                            try {
                                                var inst = mtd.Body.Instructions[i];
                                                if (inst.OpCode == OpCodes.Call) {
                                                    if (inst.Operand == stringDecryptMtd) {
                                                        string decrypted = (string)reflectiveStringDecrypt.Invoke(null, new object[] { mtd.Body.Instructions[i - 1].GetLdcI4Value() });
                                                        Console.WriteLine("String decrypted: " + decrypted);
                                                        mtd.Body.Instructions[i - 1].OpCode = OpCodes.Nop; // pad cause can't remove :broken_heart:
                                                        inst.OpCode = OpCodes.Ldstr;
                                                        inst.Operand = decrypted;
                                                    }
                                                }
                                            } catch { }
                                        }
                                    }
                                }
                                continue;
                            }

                            // Decrypt constants
                            MethodDef intDecryptMtd = type.Methods.FirstOrDefault(x => x.ReturnType == module.CorLibTypes.Int32 && x.Parameters.Count == 1 && x.Parameters[0].Type == module.CorLibTypes.Int32),
                                      longDecryptMtd = type.Methods.FirstOrDefault(x => x.ReturnType == module.CorLibTypes.Int64 && x.Parameters.Count == 1 && x.Parameters[0].Type == module.CorLibTypes.Int32),
                                      floatDecryptMtd = type.Methods.FirstOrDefault(x => x.ReturnType == module.CorLibTypes.Single && x.Parameters.Count == 1 && x.Parameters[0].Type == module.CorLibTypes.Int32),
                                      doubleDecryptMtd = type.Methods.FirstOrDefault(x => x.ReturnType == module.CorLibTypes.Double && x.Parameters.Count == 1 && x.Parameters[0].Type == module.CorLibTypes.Int32);

                            if (intDecryptMtd != null && longDecryptMtd != null && floatDecryptMtd != null && doubleDecryptMtd != null) {
                                MethodInfo reflectiveIntDecrypt = decryptType.GetMethod(intDecryptMtd.Name, BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static),
                                      reflectiveLongDecrypt = decryptType.GetMethod(longDecryptMtd.Name, BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static),
                                      reflectiveFloatDecrypt = decryptType.GetMethod(floatDecryptMtd.Name, BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static),
                                      reflectiveDoubleDecrypt = decryptType.GetMethod(doubleDecryptMtd.Name, BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);

                                foreach (var type2 in module.Types) {
                                    foreach (var mtd in type2.Methods) {
                                        if (!mtd.HasBody)
                                            continue;
                                        for (int i = 0; i < mtd.Body.Instructions.Count; i++) {
                                            try {
                                                var inst = mtd.Body.Instructions[i];
                                                if (inst.OpCode == OpCodes.Call) {
                                                    if (inst.Operand == intDecryptMtd) {
                                                        int decrypted = (int)reflectiveIntDecrypt.Invoke(null, new object[] { mtd.Body.Instructions[i - 1].Operand });
                                                        Console.WriteLine("Int decrypted: " + decrypted);
                                                        mtd.Body.Instructions[i - 1].OpCode = OpCodes.Nop;
                                                        inst.OpCode = OpCodes.Ldc_I4;
                                                        inst.Operand = decrypted;
                                                    } else if (inst.Operand == longDecryptMtd) {
                                                        long decrypted = (long)reflectiveLongDecrypt.Invoke(null, new object[] { mtd.Body.Instructions[i - 1].Operand });
                                                        Console.WriteLine("Long decrypted: " + decrypted);
                                                        mtd.Body.Instructions[i - 1].OpCode = OpCodes.Nop;
                                                        inst.OpCode = OpCodes.Ldc_I8;
                                                        inst.Operand = decrypted;
                                                    } else if (inst.Operand == floatDecryptMtd) {
                                                        float decrypted = (float)reflectiveLongDecrypt.Invoke(null, new object[] { mtd.Body.Instructions[i - 1].Operand });
                                                        Console.WriteLine("Float decrypted: " + decrypted);
                                                        mtd.Body.Instructions[i - 1].OpCode = OpCodes.Nop;
                                                        inst.OpCode = OpCodes.Ldc_R4;
                                                        inst.Operand = decrypted;
                                                    } else if (inst.Operand == doubleDecryptMtd) {
                                                        double decrypted = (double)reflectiveLongDecrypt.Invoke(null, new object[] { mtd.Body.Instructions[i - 1].Operand });
                                                        Console.WriteLine("Double decrypted: " + decrypted);
                                                        mtd.Body.Instructions[i - 1].OpCode = OpCodes.Nop;
                                                        inst.OpCode = OpCodes.Ldc_R8;
                                                        inst.Operand = decrypted;
                                                    }
                                                }
                                            } catch { }
                                        }
                                    }
                                }
                                continue;
                            }
                        }
                    }
                } catch (Exception e) {
                    Console.WriteLine("Failed to load assembly, skipping the decryption: " + e.Message);
                }
                module.Write(Path.Combine(Path.GetDirectoryName(args[0]), Path.GetFileNameWithoutExtension(args[0]) + "-deobf.exe"));
            } catch (Exception e) {
                Console.WriteLine("CryptoDeobfuscator failed: " + e);
            }

            Console.ReadLine();
        }
    }
}