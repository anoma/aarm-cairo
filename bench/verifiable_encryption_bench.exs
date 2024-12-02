{:ok, program} = File.read("./juvix/encryption.json")

{:ok, input} =
  File.read("./juvix/encryption_input.json")

{_output, trace, memory, public_inputs} =
  Cairo.cairo_vm_runner(
    program,
    input
  )

# Prove and verify
{proof, public_input} = Cairo.prove(trace, memory, public_inputs)

sk = :binary.bin_to_list(<<1::256>>)

cipher = Cairo.get_output(public_input)

Benchee.run(
  %{
    "encryption circuit: run cairo vm" => fn ->
      Cairo.cairo_vm_runner(program, input)
    end
  },
  warmup: 1,
  time: 10
)

Benchee.run(
  %{
    "encryption circuit: prover" => fn ->
      Cairo.prove(trace, memory, public_inputs)
    end
  },
  warmup: 1,
  time: 10
)

Benchee.run(
  %{
    "encryption circuit: verifier" => fn ->
      Cairo.verify(proof, public_input)
    end
  },
  warmup: 1,
  time: 10
)

Benchee.run(
  %{
    "decryption" => fn ->
      Cairo.decrypt(cipher, sk)
    end
  },
  warmup: 1,
  time: 10
)
