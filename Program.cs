using Konscious.Security.Cryptography;
using Scrypt;
using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

try
{
    var scryptInput = new ScryptInput();
    var argon2Input = new Argon2Input();
    var saltString = "somesalt";

    foreach (var arg in args)
    {
        if (!Regex.IsMatch(arg, "^-([Nrpmidt][1-9][0-9]*|s.+)$"))
        {
            WriteError($"Invalid argument: '{arg}'.");
            WriteHelp();
            return 1;
        }

        var data = arg[2..];

        switch (arg[1])
        {
            case 'N':
                scryptInput.IterationCount = int.Parse(data);
                break;

            case 'r':
                scryptInput.BlockSize = int.Parse(data);
                break;

            case 'p':
                scryptInput.ThreadCount = int.Parse(data);
                break;

            case 't':
                ScryptEncoder.MaxDegreeOfParallelism = int.Parse(data);
                break;

            case 'm':
                argon2Input.MemorySize = int.Parse(data);
                break;

            case 'i':
                argon2Input.Iterations = int.Parse(data);
                break;

            case 'd':
                argon2Input.DegreeOfParallelism = int.Parse(data);
                break;

            case 's':
                saltString = data;
                break;

            default:
                throw new Exception($"This should not happen.");
        }
    }

    var salt = SHA256.HashData(Encoding.UTF8.GetBytes(saltString));
    Console.WriteLine($"scrypt CPU/memory cost       = {scryptInput.IterationCount}");
    Console.WriteLine($"scrypt block size            = {scryptInput.BlockSize}");
    Console.WriteLine($"scrypt parallelization       = {scryptInput.ThreadCount}");
    Console.WriteLine($"scrypt threads               = {ScryptEncoder.MaxDegreeOfParallelism}");
    Console.WriteLine($"argon2 memory size           = {argon2Input.MemorySize}");
    Console.WriteLine($"argon2 iterations            = {argon2Input.Iterations}");
    Console.WriteLine($"argon2 degree of parallelism = {argon2Input.DegreeOfParallelism}");
    Console.WriteLine($"salt                         = {Convert.ToBase64String(salt)}");
    Console.WriteLine();

    Console.WriteLine("Please enter a password to hash:");
    var password = Console.ReadLine();

    if (string.IsNullOrEmpty(password))
    {
        return 1;
    }

    var stopwatch = Stopwatch.StartNew();
    var scryptEncoder = new ScryptEncoder(scryptInput.IterationCount, scryptInput.BlockSize, scryptInput.ThreadCount);
    var scryptHash = Convert.FromBase64String(scryptEncoder.Encode(password, salt).Split('$')[^1]);
    Console.WriteLine($"Scrypt hash = {Convert.ToBase64String(scryptHash)} (hashing took {stopwatch.ElapsedMilliseconds:N0} ms)");
    stopwatch.Restart();

    var argon2 = new Argon2d(Encoding.UTF8.GetBytes(password))
    {
        DegreeOfParallelism = argon2Input.DegreeOfParallelism,
        Iterations = argon2Input.Iterations,
        MemorySize = argon2Input.MemorySize,
        Salt = salt,
    };
    var argon2Hash = argon2.GetBytes(32);
    Console.WriteLine($"Argon2 hash = {Convert.ToBase64String(argon2Hash)} (hashing took {stopwatch.ElapsedMilliseconds:N0} ms)");

    var finalHash = scryptHash.Zip(argon2Hash, (x, y) => (byte)(x ^ y)).ToArray();
    Console.WriteLine($"Final hash  = {Convert.ToBase64String(finalHash)}");

    return 0;
}
catch (Exception ex)
{
    WriteError(ex);
    return 1;
}

static void WriteHelp()
{
    Console.WriteLine();
    Console.WriteLine("Example usage: key-stretcher -N1024 -r8 -p1 -t1 -i1 -m1024 -d1 -ssomesalt");
    Console.WriteLine("Optional parameters:");
    Console.WriteLine("-N  scrypt CPU/memory cost");
    Console.WriteLine("-r  scrypt block size");
    Console.WriteLine("-p  scrypt parallelization");
    Console.WriteLine("-t  scrypt threads (can be modified without affecting the hash)");
    Console.WriteLine("-m  argon2 memory size in KiB");
    Console.WriteLine("-i  argon2 iterations");
    Console.WriteLine("-d  argon2 degree of parallelism");
    Console.WriteLine("-s  salt");
}

static void WriteError(object message) => Console.Error.WriteLine($"Error: {message}");

class ScryptInput
{
    public int IterationCount { get; set; } = 1024;
    public int BlockSize { get; set; } = 8;
    public int ThreadCount { get; set; } = 1;
}

class Argon2Input
{
    public int Iterations { get; set; } = 1;
    public int MemorySize { get; set; } = 1024;
    public int DegreeOfParallelism { get; set; } = 1;
}