import unittest
import PyKCS11


class Testutil(unittest.TestCase):

    def test_empty(self):
        ck = PyKCS11.ckbytelist()
        self.assertSequenceEqual(ck, [])

    def test_resize(self):
        ck = PyKCS11.ckbytelist()
        ck.resize(5)
        self.assertSequenceEqual(ck, [0, 0, 0, 0, 0])

    def test_data(self):
        ck = PyKCS11.ckbytelist(5)
        for index in range(5):
            ck[index] = index
        self.assertSequenceEqual(ck, [0, 1, 2, 3, 4])

    def test_append(self):
        ck = PyKCS11.ckbytelist()
        for index in range(5):
            ck.append(index)
        self.assertSequenceEqual(ck, [0, 1, 2, 3, 4])

    def test_length0(self):
        ck = PyKCS11.ckbytelist()
        self.assertEqual(len(ck), 0)

    def test_length5(self):
        ck = PyKCS11.ckbytelist(5)
        self.assertEqual(len(ck), 5)

    def test_string(self):
        ck = PyKCS11.ckbytelist()
        ck.resize(5)
        for index in range(5):
            ck[index] = index
        self.assertEqual(str(ck), "[0, 1, 2, 3, 4]")

    def test_init_list0(self):
        ck = PyKCS11.ckbytelist([])
        self.assertSequenceEqual(ck, [])

    def test_init_list1(self):
        ck = PyKCS11.ckbytelist([1])
        self.assertSequenceEqual(ck, [1])

    def test_init_list5(self):
        ck = PyKCS11.ckbytelist([0, 1, 2, 3, 4])
        self.assertSequenceEqual(ck, [0, 1, 2, 3, 4])

    def test_init_str(self):
        ck = PyKCS11.ckbytelist("ABC")
        self.assertSequenceEqual(ck, [65, 66, 67])

    def test_init_bytes(self):
        ck = PyKCS11.ckbytelist(b"ABC")
        self.assertSequenceEqual(ck, [65, 66, 67])


if __name__ == '__main__':
    unittest.main()
