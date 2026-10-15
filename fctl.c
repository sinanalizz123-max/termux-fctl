/* fctl: minimal Frida controller for Termux (talks to frida-gadget over TCP).
 *
 * Usage: fctl <script.js> [output]
 * Connects to 127.0.0.1:27042 (gadget default), attaches to the gadget's own
 * process, loads the script, prints messages, appends payload lines to output.
 */
#include "frida-core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static GMainLoop *loop = NULL;
static FILE *out = NULL;

static void
on_message (FridaScript *script, const gchar *message, GBytes *data,
            gpointer user_data)
{
  JsonParser *parser;
  JsonNode *root;
  JsonObject *obj;
  const gchar *type;
  (void) script;
  (void) user_data;
  (void) data;

  parser = json_parser_new ();
  if (!json_parser_load_from_data (parser, message, -1, NULL))
  {
    g_print ("[raw] %s\n", message);
    g_object_unref (parser);
    return;
  }
  root = json_parser_get_root (parser);
  obj = json_node_get_object (root);
  type = json_object_get_string_member (obj, "type");
  if (g_strcmp0 (type, "send") == 0)
  {
    JsonNode *payload = json_object_get_member (obj, "payload");
    if (JSON_NODE_HOLDS_VALUE (payload))
    {
      const gchar *s = json_node_get_string (payload);
      g_print ("%s\n", s);
      if (out != NULL)
      {
        fprintf (out, "%s\n", s);
        fflush (out);
      }
    }
    else
    {
      gchar *dump = json_to_string (payload, FALSE);
      g_print ("%s\n", dump);
      g_free (dump);
    }
  }
  else if (g_strcmp0 (type, "error") == 0)
  {
    g_print ("[script-error] %s\n", message);
  }
  g_object_unref (parser);
}

static gchar *
read_file (const char *path)
{
  GError *error = NULL;
  gchar *contents = NULL;
  gsize length = 0;
  if (!g_file_get_contents (path, &contents, &length, &error))
  {
    g_printerr ("cannot read %s: %s\n", path, error->message);
    exit (1);
  }
  return contents;
}

int
main (int argc, char *argv[])
{
  FridaDeviceManager *manager;
  FridaDevice *device;
  FridaProcessList *procs;
  FridaSession *session;
  FridaScript *script;
  GError *error = NULL;
  gchar *source;
  const char *outpath;

  if (argc < 2)
  {
    g_printerr ("Usage: %s <script.js> [output]\n", argv[0]);
    return 1;
  }
  outpath = argc > 2 ? argv[2] : NULL;
  if (outpath != NULL)
  {
    out = fopen (outpath, "a");
    if (out == NULL)
    {
      g_printerr ("cannot open %s\n", outpath);
      return 1;
    }
  }

  frida_init ();
  loop = g_main_loop_new (NULL, FALSE);

  manager = frida_device_manager_new ();
  device = frida_device_manager_add_remote_device_sync (
      manager, "127.0.0.1", NULL, NULL, &error);
  if (error != NULL)
  {
    g_printerr ("remote device failed: %s\n", error->message);
    return 1;
  }

  /* Gadget exposes only its own process; attach to the first non-gadget... */
  procs = frida_device_enumerate_processes_sync (device, NULL, NULL, &error);
  if (error != NULL)
  {
    g_printerr ("enumerate failed: %s\n", error->message);
    return 1;
  }
  {
    gint n = frida_process_list_size (procs);
    gint i;
    g_print ("%d processes on gadget device\n", n);
    for (i = 0; i < n; i++)
    {
      FridaProcess *p = frida_process_list_get (procs, i);
      g_print ("  pid=%u name=%s\n", frida_process_get_pid (p),
               frida_process_get_name (p));
    }
  }

  /* Embedded gadget: attach straight to the PID given in argv[3] (or the
   * sole enumerated process). Enumerate first only to discover it. */
  {
    gint n = 0;
    guint target = 0;
    if (argc > 3)
      target = (guint) atoi (argv[3]);
    if (target == 0)
    {
      procs = frida_device_enumerate_processes_sync (device, NULL, NULL,
                                                    &error);
      if (error != NULL)
      {
        g_printerr ("enumerate failed: %s (continuing - pass PID as argv[3])\n",
                    error->message);
        g_clear_error (&error);
      }
      else
      {
        gint i;
        n = frida_process_list_size (procs);
        for (i = 0; i < n; i++)
        {
          FridaProcess *p = frida_process_list_get (procs, i);
          g_print ("  pid=%u name=%s\n", frida_process_get_pid (p),
                   frida_process_get_name (p));
          if (target == 0)
            target = frida_process_get_pid (p);
        }
      }
    }
    if (target == 0)
    {
      g_printerr ("no process to attach to\n");
      return 1;
    }
    g_print ("attaching to pid %u\n", target);
    session = frida_device_attach_sync (device, target, NULL, NULL, &error);
  }
  if (error != NULL)
  {
    g_printerr ("attach failed: %s\n", error->message);
    return 1;
  }
  g_print ("attached, session %p\n", (void *) session);

  source = read_file (argv[1]);
  script = frida_session_create_script_sync (session, source, NULL, NULL,
                                                   &error);
  g_free (source);
  if (error != NULL)
  {
    g_printerr ("create_script failed: %s\n", error->message);
    return 1;
  }
  g_signal_connect (script, "message", G_CALLBACK (on_message), NULL);
  frida_script_load_sync (script, NULL, &error);
  if (error != NULL)
  {
    g_printerr ("load failed: %s\n", error->message);
    return 1;
  }
  g_print ("script loaded, listening...\n");
  g_main_loop_run (loop);
  return 0;
}
