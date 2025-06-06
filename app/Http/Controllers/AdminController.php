<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;

class AdminController extends Controller
{
    // Tampilkan daftar dosen
    public function dosenIndex()
    {
        $dosen = User::role('dosen')->get();
        return view('admin.dosen.index', compact('dosen'));
    }

    // Tampilkan daftar mahasiswa
    public function mahasiswaIndex()
    {
        $mahasiswa = User::role('mahasiswa')->get();
        return view('admin.mahasiswa.index', compact('mahasiswa'));
    }

    // Form tambah dosen
    public function create()
    {
        return view('admin.dosen.create');
    }

    // Form tambah mahasiswa
    public function createMahasiswa()
    {
        return view('admin.mahasiswa.create');
    }

    // Simpan dosen baru
    public function storeDosen(Request $request)
    {
        $request->validate([
            'nip' => 'required|unique:users,nip',
            'name' => 'required',
            'email_prefix' => 'required|alpha_dash|unique:users,email',
            'password' => 'required|min:6',
        ]);

        $email = strtolower($request->email_prefix) . '@it.lecturer.pens.ac.id';

        $user = User::create([
            'nip' => $request->nip,
            'name' => $request->name,
            'email' => $email,
            'password' => Hash::make($request->password),
        ]);
        $user->assignRole('dosen');

        return redirect()->route('admin.dosen.index')->with('success', 'Dosen berhasil ditambahkan');
    }

    // Simpan mahasiswa baru
    public function storeMahasiswa(Request $request)
    {
        $request->validate([
            'nrp' => 'required|unique:users,nrp',
            'name' => 'required',
            'email_prefix' => 'required|alpha_dash|unique:users,email',
            'password' => 'required|min:6',
        ]);

        $email = strtolower($request->email_prefix) . '@it.student.pens.ac.id';

        $user = User::create([
            'nrp' => $request->nrp,
            'name' => $request->name,
            'email' => $email,
            'password' => Hash::make($request->password),
        ]);
        $user->assignRole('mahasiswa');

        return redirect()->route('admin.mahasiswa.index')->with('success', 'Mahasiswa berhasil ditambahkan');
    }

    // Edit dosen
    public function editDosen($id)
    {
        $dosen = User::findOrFail($id);
        return view('admin.dosen.edit', compact('dosen'));
    }

    // Update dosen
    public function updateDosen(Request $request, $id)
    {
        $dosen = User::findOrFail($id);

        $request->validate([
            'nip' => 'required|unique:users,nip,' . $dosen->id,
            'name' => 'required',
            'email_prefix' => 'required|alpha_dash|unique:users,email,' . $dosen->id,
        ]);

        $email = strtolower($request->email_prefix) . '@it.lecturer.pens.ac.id';

        $data = [
            'nip' => $request->nip,
            'name' => $request->name,
            'email' => $email,
        ];

        if ($request->filled('password')) {
            $data['password'] = Hash::make($request->password);
        }

        $dosen->update($data);

        return redirect()->route('admin.dosen.index')->with('success', 'Dosen berhasil diupdate');
    }

    // Hapus dosen
    public function destroyDosen($id)
    {
        $dosen = User::findOrFail($id);
        $dosen->delete();
        return redirect()->route('admin.dosen.index')->with('success', 'Dosen berhasil dihapus');
    }

    // Edit mahasiswa
    public function editMahasiswa($id)
    {
        $mahasiswa = User::findOrFail($id);
        return view('admin.mahasiswa.edit', compact('mahasiswa'));
    }

    // Update mahasiswa
    public function updateMahasiswa(Request $request, $id)
    {
        $mahasiswa = User::findOrFail($id);

        $request->validate([
            'nrp' => 'required|unique:users,nrp,' . $mahasiswa->id,
            'name' => 'required',
            'email_prefix' => 'required|alpha_dash|unique:users,email,' . $mahasiswa->id,
        ]);

        $email = strtolower($request->email_prefix) . '@it.student.pens.ac.id';

        $data = [
            'nrp' => $request->nrp,
            'name' => $request->name,
            'email' => $email,
        ];

        if ($request->filled('password')) {
            $data['password'] = Hash::make($request->password);
        }

        $mahasiswa->update($data);

        return redirect()->route('admin.mahasiswa.index')->with('success', 'Mahasiswa berhasil diupdate');
    }

    // Hapus mahasiswa
    public function destroyMahasiswa($id)
    {
        $mahasiswa = User::findOrFail($id);
        $mahasiswa->delete();
        return redirect()->route('admin.mahasiswa.index')->with('success', 'Mahasiswa berhasil dihapus');
    }

    // Dashboard
    public function dashboard()
    {
        return view('admin.dashboard');
    }

    public function matakuliah()
    {
        return view('admin.matakuliah');
    }

    public function frs()
    {
        return view('admin.frs');
    }
}